require 'nginx_omniauth_adapter'
require 'omniauth'
require 'omniauth/version'
require 'open-uri'
require 'json'

dev = ENV['NGX_OMNIAUTH_DEV'] == '1' || ENV['RACK_ENV'] == 'development'
test = ENV['RACK_ENV'] == 'test'

# We intentionally allow GET for login, knowing CVE-2015-9284.
OmniAuth.config.allowed_request_methods = [:get, :post]
if Gem::Version.new(OmniAuth::VERSION) >= Gem::Version.new("2.0.0")
  OmniAuth.config.silence_get_warning = true
end

if test
  dev = true
  warn 'TEST MODE'
  OmniAuth.config.test_mode = true
  OmniAuth.config.mock_auth[:developer] = {provider: 'developer', uid: '42', info: {}}
end

if !dev && !ENV['NGX_OMNIAUTH_SESSION_SECRET']
  raise 'You should specify $NGX_OMNIAUTH_SESSION_SECRET'
end

allowed_app_callback_url = if ENV['NGX_OMNIAUTH_ALLOWED_APP_CALLBACK_URL']
                             Regexp.new(ENV['NGX_OMNIAUTH_ALLOWED_APP_CALLBACK_URL'])
                           else
                             nil
                           end

allowed_back_to_url      = if ENV['NGX_OMNIAUTH_ALLOWED_BACK_TO_URL']
                             Regexp.new(ENV['NGX_OMNIAUTH_ALLOWED_BACK_TO_URL'])
                           else
                             nil
                           end

use(
  Rack::Session::Cookie,
  key:          ENV['NGX_OMNIAUTH_SESSION_COOKIE_NAME'] || 'ngx_omniauth',
  expire_after: ENV['NGX_OMNIAUTH_SESSION_COOKIE_TIMEOUT'] ? ENV['NGX_OMNIAUTH_SESSION_COOKIE_TIMEOUT'].to_i : (60 * 60 * 24 * 3),
  secret:       ENV['NGX_OMNIAUTH_SESSION_SECRET'] || 'ngx_omniauth_secret_dev',
  old_secret:   ENV['NGX_OMNIAUTH_SESSION_SECRET_OLD'],
)

providers = []

gh_teams = ENV['NGX_OMNIAUTH_GITHUB_TEAMS'] && ENV['NGX_OMNIAUTH_GITHUB_TEAMS'].split(/[, ]/)

use OmniAuth::Builder do
  if ENV['NGX_OMNIAUTH_GITHUB_KEY'] && ENV['NGX_OMNIAUTH_GITHUB_SECRET']
    require 'omniauth-github'
    gh_client_options = {}
    if ENV['NGX_OMNIAUTH_GITHUB_HOST']
      gh_client_options[:site] = "#{ENV['NGX_OMNIAUTH_GITHUB_HOST']}/api/v3"
      gh_client_options[:authorize_url] = "#{ENV['NGX_OMNIAUTH_GITHUB_HOST']}/login/oauth/authorize"
      gh_client_options[:token_url] = "#{ENV['NGX_OMNIAUTH_GITHUB_HOST']}/login/oauth/access_token"
    end

    gh_scope = ''
    if ENV['NGX_OMNIAUTH_GITHUB_TEAMS']
      gh_scope = 'read:org'
    end

    provider :github, ENV['NGX_OMNIAUTH_GITHUB_KEY'], ENV['NGX_OMNIAUTH_GITHUB_SECRET'], client_options: gh_client_options, scope: gh_scope
    providers << :github
  end

  if ENV['NGX_OMNIAUTH_GOOGLE_KEY'] && ENV['NGX_OMNIAUTH_GOOGLE_SECRET']
    require 'omniauth-google-oauth2'
    provider :google_oauth2, ENV['NGX_OMNIAUTH_GOOGLE_KEY'], ENV['NGX_OMNIAUTH_GOOGLE_SECRET'], hd: ENV['NGX_OMNIAUTH_GOOGLE_HD']
    providers << :google_oauth2
  end

  if dev
    provider :developer
    providers << :developer
  end
end

run NginxOmniauthAdapter.app(
  providers: providers,
  provider_http_header: ENV['NGX_OMNIAUTH_PROVIDER_HTTP_HEADER'] || 'x-ngx-omniauth-provider',
  secret: ENV['NGX_OMNIAUTH_SECRET'],
  host: ENV['NGX_OMNIAUTH_HOST'],
  allowed_app_callback_url: allowed_app_callback_url,
  allowed_back_to_url: allowed_back_to_url,
  app_refresh_interval: ENV['NGX_OMNIAUTH_APP_REFRESH_INTERVAL'] && ENV['NGX_OMNIAUTH_APP_REFRESH_INTERVAL'].to_i,
  adapter_refresh_interval: ENV['NGX_OMNIAUTH_ADAPTER_REFRESH_INTERVAL'] && ENV['NGX_OMNIAUTH_APP_REFRESH_INTERVAL'].to_i,
  policy_proc: proc {
    if gh_teams && current_user[:provider] == 'github'
      unless (current_user_data[:gh_teams] || []).any? { |team| gh_teams.include?(team) }
        next false
      end
    end

    true
  },
  on_login_proc: proc {
    auth = env['omniauth.auth']
    case auth[:provider]
    when 'github'
      if gh_teams
        api_host = ENV['NGX_OMNIAUTH_GITHUB_HOST'] ? "#{ENV['NGX_OMNIAUTH_GITHUB_HOST']}/api/v3" : "https://api.github.com"
        current_user_data[:gh_teams] = open("#{api_host}/user/teams", 'Authorization' => "token #{auth['credentials']['token']}") { |io|
          JSON.parse(io.read).map {|_| "#{_['organization']['login']}/#{_['slug']}" }.select { |team| gh_teams.include?(team) }
        }
      end
    end

    true
  },
)
