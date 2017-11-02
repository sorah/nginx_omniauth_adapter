require 'sinatra/base'
require 'uri'
require 'time'
require 'openssl'
require 'json'
require 'securerandom'

require 'rack/utils'

require 'nginx_omniauth_adapter/token'

module NginxOmniauthAdapter
  class App < Sinatra::Base
    CONTEXT_RACK_ENV_NAME = 'nginx-omniauth-adapter'.freeze

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

      def jwt_cookie_name
        adapter_config[:token_cookie_name] || 'ngxotoken'
      end

      def jwt_hmac_secret
        adapter_config[:jwt_hmac_secret] || secret_key
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
        current_jwt_user
      end

      def current_legacy_user
        session[:user]
      end

      def jwt_string
        request.env['HTTP_X_NGXO_TOKEN'] || request.env['HTTP_X_NGX_OMNIAUTH_TOKEN'] || request.cookies[jwt_cookie_name]
      end

      def master_request?
        @master_request
      end

      def current_token
        @token ||= if jwt_string
          token, error = Token.decode(
            jwt_string,
            master: master_request?,
            keys: {default: jwt_hmac_secret},
          )
          error ? nil : token
        end
      end

      def secure_cookie?
        adapter_config.fetch(:secure, request.ssl?)
      end

      def current_jwt_user
        current_token && current_token.user
      end

      def current_user_data
        @current_user_data ||= (current_token ? current_token.context : session[:user_data]) || {}
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
        app_refresh_interval && !current_jwt_user && current_user && (Time.now - current_authorized_at) > app_refresh_interval
      end

      def adapter_authorization_expired?
        adapter_refresh_interval && !current_jwt_user && current_user && (Time.now - current_logged_in_at) > adapter_refresh_interval
      end

      def set_token(context: nil, user: , expires_in: nil)
        token, token_string = Token.issue(
          master: true,
          key: jwt_hmac_secret,
          expires_in: expires_in || adapter_refresh_interval,
          user: user,
          context: context,
        )
        @token = token
        response.set_cookie(
          jwt_cookie_name,
          path: '/',
          http_only: true,
          expire_after: expires_in || adapter_refresh_interval,
          secure: secure_cookie?,
          value: token_string,
        )
      end

      def jwt_migration!
        if current_logged_in_at && current_legacy_user
        session[:user] = nil
      end

      def update_session!(auth = nil)
        unless session[:app_callback]
          log severity: :error, message: 'missing app_callback'
          raise '[BUG] app_callback is missing'
        end

        if auth
          user = {
            uid: auth[:uid],
            info: auth[:info],
            provider: auth[:provider],
          }

          set_token(
            context: current_user_data,
            user: user,
          )
        else
          user = current_user
        end

        _, app_token = Token.issue(
          master: false,
          parent_id: current_jwt_user.id,
          key: jwt_hmac_secret,
          expires_in: app_refresh_interval,
          user: user,
          context: current_user_data,
        )

        back_to = session.delete(:back_to)
        signature = OpenSSL::HMAC.hexdigest("sha256", secret_key, "token:#{app_token}\nback_to:#{back_to}")

        log(message: 'update_session', app_callback: session[:app_callback])

        session.options[:drop] = true
        redirect "#{session.delete(:app_callback)}?token=#{URI.encode_www_form_component(app_token)}&back_to=#{URI.encode_www_form_component(back_to)}&signature=#{signature}"
      ensure
        session[:flow_id] = nil
      end

      def secret_key
        @secret_key ||= begin
          if adapter_config[:secret]
            adapter_config[:secret].unpack('m*')[0]
          else
            warn "WARN: :secret not set; generating randomly."
            warn "      If you'd like to persist, set `openssl rand -base64 512` . Note that you have to keep it secret."

            adapter_config[:secret] = OpenSSL::Random.random_bytes(512)
          end
        end
      end
    end

    get '/' do
      @master_request = true
      content_type :text
      "NginxOmniauthAdapter #{NginxOmniauthAdapter::VERSION}\n#{current_jwt_user.inspect}"
    end

    get '/test' do
      session.options[:drop] = true
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
      session.options[:drop] = true
      back_to = request.env['HTTP_X_NGX_OMNIAUTH_INITIATE_BACK_TO']
      callback = request.env['HTTP_X_NGX_OMNIAUTH_INITIATE_CALLBACK']

      if back_to == '' || callback == '' || back_to.nil? || callback.nil?
        log(severity: :error, message: 'initiate_no_required_params', back_to: back_to, callback: callback)
        halt 400, {'Content-Type' => 'text/plain'}, 'x-ngx-omniauth-initiate-back-to and x-ngx-omniauth-initiate-callback header are required'
      end

      log(message: 'initiate', adapter_host: adapter_host, back_to: back_to, callback: callback)

      signature = OpenSSL::HMAC.hexdigest("sha256", secret_key, "back_to:#{back_to}\ncallback:#{callback}")

      redirect "#{adapter_host}/auth?back_to=#{URI.encode_www_form_component(back_to)}&callback=#{URI.encode_www_form_component(callback)}&signature=#{signature}"
    end

    get '/auth' do
      @master_request = true
      #session.options[:drop] = true

      # TODO: choose provider
      back_to = sanitized_back_to_param
      app_callback = sanitized_app_callback_param

      signature = OpenSSL::HMAC.hexdigest("sha256", secret_key, "back_to:#{back_to}\ncallback:#{app_callback}")
      if !Rack::Utils.secure_compare(params[:signature], signature)
        log(severity: :error, message: 'auth_invalid_sign', back_to: params[:back_to], callback: params[:callback], signature: params[:signature], correct_signature: signature)
        halt 400, {'Content-Type' => 'text/plain'}, 'signature mismatch'
      end

      if back_to == '' || app_callback == '' || back_to.nil? || app_callback.nil?
        log(severity: :error, message: 'auth_invalid_params', back_to: params[:back_to], callback: params[:callback])
        halt 400, {'Content-Type' => 'text/plain'}, 'back_to or/and app_callback is invalid'
      end

      jwt_migration!
      set_flow_id!

      session[:back_to] =  back_to
      session[:app_callback] = app_callback

      if current_user && !adapter_authorization_expired?
        log(message: 'auth_refresh_app', back_to: params[:back_to], callback: params[:callback])
        update_session!
      else
        log(message: 'auth', provider: providers[0], back_to: params[:back_to], callback: params[:callback])
        redirect "#{adapter_host}/auth/#{providers[0]}"
      end
    end

    omniauth_callback = proc do
      @master_request = true
      jwt_migration!

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
      session.options[:drop] = true

      app_token = params[:token]
      back_to = params[:back_to]

      signature = OpenSSL::HMAC.hexdigest("sha256", secret_key, "token:#{app_token}\nback_to:#{back_to}")
      if !Rack::Utils.secure_compare(params[:signature], signature)
        log(severity: :error, message: 'app_callback_invalid_sign', back_to: params[:back_to], signature: params[:signature], correct_signature: signature)
        halt 400, {'Content-Type' => 'text/plain'}, 'signature mismatch'
      end

      response.set_cookie(
        jwt_cookie_name,
        path: '/',
        http_only: true,
        expire_after: app_refresh_interval,
        secure: secure_cookie?,
        value: app_token,
      )

      log(message: 'app_callback', back_to: session[:back_to])
      redirect session.delete(:back_to)
    end
  end
end
