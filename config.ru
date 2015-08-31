require 'nginx_omniauth_adapter'
require 'omniauth'

dev = ENV['NGINX_OAUTH2_ADAPTER_DEV'] == '1' || ENV['RACK_ENV'] == 'development'
test = ENV['RACK_ENV'] == 'test'

if test
  dev = true
  warn 'TEST MODE'
  OmniAuth.config.test_mode = true
  OmniAuth.config.mock_auth[:developer] = {provider: 'developer', uid: '42', info: {}}
end

if !dev && !ENV['NGINX_OAUTH2_ADAPTER_SESSION_SECRET']
  raise 'You should specify $NGINX_OAUTH2_ADAPTER_SESSION_SECRET'
end

use(
  Rack::Session::Cookie,
  key:          ENV['NGINX_OAUTH2_ADAPTER_SESSION_COOKIE_NAME'] || 'ngx_oauth',
  expire_after: ENV['NGINX_OAUTH2_ADAPTER_SESSION_COOKIE_TIMEOUT'] ? ENV['NGINX_OAUTH2_ADAPTER_SESSION_COOKIE_TIMEOUT'].to_i : (60 * 60 * 24 * 3),
  secret:       ENV['NGINX_OAUTH2_ADAPTER_SESSION_SECRET'] || 'ngx_oauth_secret_dev',
  old_secret:   ENV['NGINX_OAUTH2_ADAPTER_SESSION_SECRET_OLD'],
)

use OmniAuth::Builder do
  if dev
    provider :developer
  end
end

run NginxOmniauthAdapter.app(
  providers: %i(developer),
  secret: ENV['NGINX_OAUTH2_ADAPTER_SECRET'],
  host: ENV['NGINX_OAUTH2_ADAPTER_HOST'],
)
