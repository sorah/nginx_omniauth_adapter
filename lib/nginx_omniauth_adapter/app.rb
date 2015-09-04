require 'sinatra/base'
require 'uri'
require 'time'
require 'openssl'
require 'json'
require 'securerandom'

module NginxOmniauthAdapter
  class App < Sinatra::Base
    CONTEXT_RACK_ENV_NAME = 'nginx-omniauth-adapter'.freeze
    SESSION_PASS_CIPHER_ALGORITHM = 'aes-256-gcm'.freeze

    set :root, File.expand_path(File.join(__dir__, '..', '..', 'app'))

    def self.initialize_context(config)
      {}.tap do |ctx|
        ctx[:config] = config
      end
    end

    def self.rack(config={})
      klass = self

      context = initialize_context(config)
      app = lambda { |env|
        env[CONTEXT_RACK_ENV_NAME] = context
        klass.call(env)
      }
    end

    helpers do
      def context
        request.env[CONTEXT_RACK_ENV_NAME]
      end

      def adapter_config
        context[:config]
      end

      def adapter_host
        adapter_config[:host]
      end

      def providers
        adapter_config[:providers]
      end

      def allowed_back_to_url
        adapter_config[:allowed_back_to_url] || /./
      end

      def allowed_app_callback_url
        adapter_config[:allowed_app_callback_url] || /./
      end

      def on_login_proc
        adapter_config[:on_login_proc] || proc { true }
      end

      def policy_proc
        adapter_config[:policy_proc] || proc { true }
      end

      def log(h={})
        h = {
          time: Time.now.xmlschema,
          severity: :info,
          logged_in: (!!current_user).inspect,
          provider: current_user && current_user[:provider],
          uid: current_user && current_user[:uid],
          flow_id: current_flow_id,
        }.merge(h)

        str = h.map { |*kv| kv.join(?:) }.join(?\t)

        puts str
        if h[:severity] == :warning || h[:severity] == :error
          $stderr.puts str
        end
      end

      def default_back_to
        # TODO:
        '/'
      end

      def sanitized_back_to_param
        if allowed_back_to_url === params[:back_to]
          params[:back_to]
        else
          nil
        end
      end

      def sanitized_app_callback_param
        if allowed_app_callback_url === params[:callback]
          params[:callback]
        else
          nil
        end
      end

      def set_flow_id!
        session[:flow_id] = SecureRandom.uuid
      end

      def current_flow_id
        session[:flow_id]
      end

      def current_user
        session[:user]
      end

      def current_user_data
        session[:user_data] ||= {}
      end

      def current_authorized_at
        session[:authorized_at] && Time.xmlschema(session[:authorized_at])
      end

      def current_logged_in_at
        session[:logged_in_at] && Time.xmlschema(session[:logged_in_at])
      end

      def app_refresh_interval
        adapter_config[:app_refresh_interval] || (60 * 60 * 24)
      end

      def adapter_refresh_interval
        adapter_config[:adapter_refresh_interval] || (60 * 60 * 24 * 30)
      end

      def app_authorization_expired?
        app_refresh_interval && current_user && (Time.now - current_authorized_at) > app_refresh_interval
      end

      def adapter_authorization_expired?
        adapter_refresh_interval && current_user && (Time.now - current_logged_in_at) > adapter_refresh_interval
      end

      def update_session!(auth = nil)
        unless session[:app_callback]
          log severity: :error, message: 'missing app_callback'
          raise '[BUG] app_callback is missing'
        end

        common_session = {
          logged_in_at: session[:logged_in_at],
          user_data: current_user_data,
        }

        if auth
          common_session[:user] = {
            uid: auth[:uid],
            info: auth[:info],
            provider: auth[:provider],
          }
        else
          common_session[:user] = session[:user]
        end

        adapter_session = common_session.merge(
          side: :adapter,
        )

        app_session = common_session.merge(
          side: :app,
          back_to: session.delete(:back_to),
          authorized_at: Time.now.xmlschema,
        )

        session.merge!(adapter_session)

        session_param = encrypt_session_param(app_session)

        log(message: 'update_session', app_callback: session[:app_callback])

        redirect "#{session.delete(:app_callback)}?session=#{session_param}"
      ensure
        session[:flow_id] = nil
      end

      def secret_key
        context[:secret_key] ||= begin
          if adapter_config[:secret]
            adapter_config[:secret].unpack('m*')[0]
          else
            cipher = OpenSSL::Cipher.new(SESSION_PASS_CIPHER_ALGORITHM)
            warn "WARN: :secret not set; generating randomly."
            warn "      If you'd like to persist, set `openssl rand -base64 #{cipher.key_len}` . Note that you have to keep it secret."

            OpenSSL::Random.random_bytes(cipher.key_len)
          end
        end
      end

      def encrypt_session_param(session_param)
        iv = nil
        cipher ||= OpenSSL::Cipher.new(SESSION_PASS_CIPHER_ALGORITHM).tap do |c|
          c.encrypt
          c.key = secret_key
          c.iv = iv = c.random_iv
          c.auth_data = ''
        end

        plaintext = Marshal.dump(session_param)

        ciphertext = cipher.update(plaintext)
        ciphertext << cipher.final

        URI.encode_www_form_component([{
          "iv" => [iv].pack('m*'),
          "data" => [ciphertext].pack('m*'),
          "tag" => [cipher.auth_tag].pack('m*'),
        }.to_json].pack('m*'))
      end

      def decrypt_session_param(raw_data)
        data = JSON.parse(raw_data.unpack('m*')[0])

        cipher ||= OpenSSL::Cipher.new(SESSION_PASS_CIPHER_ALGORITHM).tap do |c|
          c.decrypt
          c.key = secret_key
          c.iv = data['iv'].unpack('m*')[0]
          c.auth_data = ''
          c.auth_tag = data['tag'].unpack('m*')[0]
        end

        plaintext = cipher.update(data['data'].unpack('m*')[0])
        plaintext << cipher.final

        Marshal.load(plaintext)
      end

    end

    get '/' do
      content_type :text
      "NginxOmniauthAdapter #{NginxOmniauthAdapter::VERSION}"
    end

    get '/test' do
      unless current_user
        log(message: 'test_not_logged_in', original_uri: request.env['HTTP_X_NGX_OMNIAUTH_ORIGINAL_URI'])
        halt 401
      end

      if app_authorization_expired?
        log(message: 'test_app_authorization_expired', original_uri: request.env['HTTP_X_NGX_OMNIAUTH_ORIGINAL_URI'])
        halt 401
      end

      unless instance_eval(&policy_proc)
        halt 403
      end

      headers(
        'x-ngx-omniauth-provider' => current_user[:provider],
        'x-ngx-omniauth-user' => current_user[:uid],
        'x-ngx-omniauth-info' => [current_user[:info].to_json].pack('m*'),
      )

      content_type :text
      'ok'.freeze
    end

    get '/initiate' do
      back_to = URI.encode_www_form_component(request.env['HTTP_X_NGX_OMNIAUTH_INITIATE_BACK_TO'])
      callback = URI.encode_www_form_component(request.env['HTTP_X_NGX_OMNIAUTH_INITIATE_CALLBACK'])

      if back_to == '' || callback == '' || back_to.nil? || callback.nil?
        log(severity: :error, message: 'initiate_no_required_params', back_to: back_to, callback: callback)
        halt 400, {'Content-Type' => 'text/plain'}, 'x-ngx-omniauth-initiate-back-to and x-ngx-omniauth-initiate-callback header are required'
      end

      log(message: 'initiate', adapter_host: adapter_host, back_to: back_to, callback: callback)

      redirect "#{adapter_host}/auth?back_to=#{back_to}&callback=#{callback}"
    end

    get '/auth' do
      set_flow_id!

      # TODO: choose provider
      session[:back_to] = sanitized_back_to_param
      session[:app_callback] = sanitized_app_callback_param

      if session[:back_to] == '' || session[:app_callback] == '' || session[:back_to].nil? || session[:app_callback].nil?
        log(severity: :error, message: 'auth_invalid_params', back_to: params[:back_to], callback: params[:callback])
        halt 400, {'Content-Type' => 'text/plain'}, 'back_to or/and app_callback is invalid'
      end

      if current_user && !adapter_authorization_expired?
        log(message: 'auth_refresh_app', back_to: params[:back_to], callback: params[:callback])
        update_session!
      else
        log(message: 'auth', provider: providers[0], back_to: params[:back_to], callback: params[:callback])
        redirect "#{adapter_host}/auth/#{providers[0]}"
      end
    end

    omniauth_callback = proc do

      session[:user_data] = {}

      unless instance_eval(&on_login_proc)
        log(severity: :warning, message: 'omniauth_callback_forbidden', new_uid: env['omniauth.auth'][:uid])
        halt 403, {'Content-Type' => 'text/plain'}, 'Forbidden (on_login_proc policy)'
      end

      log(message: 'omniauth_callback', new_uid: env['omniauth.auth'][:uid])

      session[:logged_in_at] = Time.now.xmlschema
      update_session! env['omniauth.auth']
    end
    get '/auth/:provider/callback', &omniauth_callback
    post '/auth/:provider/callback', &omniauth_callback

    get '/callback' do # app side
      app_session = decrypt_session_param(params[:session])
      session.merge!(app_session)
      log(message: 'app_callback', back_to: session[:back_to])
      redirect session.delete(:back_to)
    end
  end
end
