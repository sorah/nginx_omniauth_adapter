require 'nginx_omniauth_adapter'
require 'omniauth'

dev = ENV['NGX_OMNIAUTH_DEV'] == '1' || ENV['RACK_ENV'] == 'development'
test = ENV['RACK_ENV'] == 'test'

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
  key:          ENV['NGX_OMNIAUTH_SESSION_COOKIE_NAME'] || 'ngx_oauth',
  expire_after: ENV['NGX_OMNIAUTH_SESSION_COOKIE_TIMEOUT'] ? ENV['NGX_OMNIAUTH_SESSION_COOKIE_TIMEOUT'].to_i : (60 * 60 * 24 * 3),
  secret:       ENV['NGX_OMNIAUTH_SESSION_SECRET'] || 'ngx_oauth_secret_dev',
  old_secret:   ENV['NGX_OMNIAUTH_SESSION_SECRET_OLD'],
)

providers = []

use OmniAuth::Builder do
  if dev
    provider :developer
    providers << :developer
  end

  if ENV['NGX_OMNIAUTH_GITHUB_KEY'] && ENV['NGX_OMNIAUTH_GITHUB_SECRET']
    gh_client_options = {}
    if ENV['NGX_OMNIAUTH_GITHUB_HOST']
      gh_client_options[:site] = "#{ENV['NGX_OMNIAUTH_GITHUB_HOST']}/api/v3"
      gh_client_options[:authorize_url] = "#{ENV['NGX_OMNIAUTH_GITHUB_HOST']}/login/oauth/authorize"
      gh_client_options[:token_url] = "#{ENV['NGX_OMNIAUTH_GITHUB_HOST']}/login/oauth/access_token"
    end

    gh_scope = ''
    # TODO:

    provider :github, ENV['NGX_OMNIAUTH_GITHUB_KEY'], ENV['NGX_OMNIAUTH_GITHUB_SECRET'], client_options: gh_client_options, scope: gh_scope
    providers << :github
  end

  if ENV['NGX_OMNIAUTH_GOOGLE_KEY'] && ENV['NGX_OMNIAUTH_GOOGLE_SECRET']
    provider :google_oauth2, ENV['NGX_OMNIAUTH_GOOGLE_KEY'], ENV['NGX_OMNIAUTH_GOOGLE_SECRET'], hd: ENV['NGX_OMNIAUTH_GOOGLE_HD']
    providers << :google_oauth2
  end
end

run NginxOmniauthAdapter.app(
  providers: providers,
  secret: ENV['NGX_OMNIAUTH_SECRET'],
  host: ENV['NGX_OMNIAUTH_HOST'],
  allowed_app_callback_url: allowed_app_callback_url,
  allowed_back_to_url: allowed_back_to_url,
  app_refresh_interval: ENV['NGX_OMNIAUTH_APP_REFRESH_INTERVAL'] && ENV['NGX_OMNIAUTH_APP_REFRESH_INTERVAL'].to_i,
  adapter_refresh_interval: ENV['NGX_OMNIAUTH_ADAPTER_REFRESH_INTERVAL'] && ENV['NGX_OMNIAUTH_APP_REFRESH_INTERVAL'].to_i,
)
