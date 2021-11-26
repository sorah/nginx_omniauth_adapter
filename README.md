# NginxOmniauthAdapter - Use omniauth for nginx `auth_request` 

[![Circle CI](https://circleci.com/gh/sorah/nginx_omniauth_adapter.svg?style=svg)](https://circleci.com/gh/sorah/nginx_omniauth_adapter)

Use [omniauth](https://github.com/intridea/omniauth) for your nginx's authentication via ngx_http_auth_request_module.

NginxOmniauthAdapter provides small Rack app (built with Sinatra) for `auth_request`.

## Prerequisite

- nginx with ngx_http_auth_request_module

## Quick example

```
$ bundle install

$ cd example/
$ foreman start
```

http://ngx-auth-test.127.0.0.1.nip.io:18080/

(make sure to have nginx on your PATH)

## Usage

### Steps

1. Start adapter app with proper configuration
2. enable `auth_request` and add some endpoints on nginx
  - See `example/nginx-site.conf` for nginx configuration.

### Running with Rubygems

```ruby
# Gemfile
gem 'nginx_omniauth_adapter'
```

Then write `config.ru` then deploy it. (see ./config.ru for example)

### Using docker

- Prebuilt: https://quay.io/repository/sorah/nginx_omniauth_adapter
  - Own your risk.
  - They're built at circleci
- Build manually: checkout this repo and run `docker build .`.
  - Much safer.
  - But if you can't trust upstream image `quay.io/sorah/rbenv:2.2`, write your own Dockerfile. This is just a simple Rack app.

## Configuration

environment variable is available only on included config.ru (or Docker image).

- `:providers`: omniauth provider names.
- `:secret` `$NGX_OMNIAUTH_SESSION_SECRET`: Rack session secret. Should be set when not on dev mode
- `:host` `$NGX_OMNIAUTH_HOST`: URL of adapter. This is used for redirection. Should include protocol (e.g. `http://example.com`.)
  - If this is not specified, adapter will perform redirect using given `Host` header.
- `:allowed_app_callback_url` `$NGX_OMNIAUTH_ALLOWED_APP_CALLBACK_URL` (regexp): If specified, URL only matches to this are allowed for app callback url.
- `:allowed_back_to_url` `$NGX_OMNIAUTH_ALLOWED_BACK_TO_URL` (regexp): If specified, URL only matches to this are allowed for back_to url.
- `:app_refresh_interval` `NGX_OMNIAUTH_APP_REFRESH_INTERVAL` (integer): Interval to require refresh session cookie on app domain (in second, default 1 day).
- `:adapter_refresh_interval` `NGX_OMNIAUTH_ADAPTER_REFRESH_INTERVAL` (integer): Interval to require re-logging in on adapter domain (in second, default 3 days).

### Included config.ru (or Docker)

You can set configuration via environment variables.

The following variables are only available on included config.ru:

- `$NGX_OMNIAUTH_SESSION_COOKIE_NAME`: session cookie name (default `ngx_omniauth`)
- `$NGX_OMNIAUTH_SESSION_COOKIE_TIMEOUT`: session cookie expiry (default 3 days)
- `$NGX_OMNIAUTH_DEV=1` or `$RACK_ENV=development`
  - enable dev mode (omniauth developer provider)
- github provider
  - `$NGX_OMNIAUTH_GITHUB_KEY`, `$NGX_OMNIAUTH_GITHUB_SECRET`: application key + secret.
  - `$NGX_OMNIAUTH_GITHUB_HOST`: (optional) Set if you'd like to use GitHub Enterprise instance (e.g. `https://YOUR-GITHUB-ENTERPRISE`)
  - `$NGX_OMNIAUTH_GITHUB_TEAMS`: (optional) Restrict to specified teams (e.g. `awesomeorganization/owners`)
- google_oauth2 provider
  - `$NGX_OMNIAUTH_GOOGLE_KEY`, `$NGX_OMNIAUTH_GOOGLE_SECRET`: oauth2 key + secret.
  - `$NGX_OMNIAUTH_GOOGLE_HD`: (optional) Restrict to specified hosted domain (Google Apps Domain).



### Manually (Rack)

If you're going to write `config.ru` from scratch, make sure:

- OmniAuth is included in middleware stack
- Rack session is enabled in middleware stack

Then run:

``` ruby
run NginxOmniauthAdapter.app(
  providers: %i(developer),
  secret: secret_base64, # optional
  # ... (set more configuration, see above variable list)
)
```

## How it works

![](http://img.sorah.jp/2015-10-08_22.55_2s4hy.png)

1. _browser_ access to restricted area (where `auth_request` has enabled)
2. _nginx_ sends subrequest to `/_auth/challenge`. It will be proxied to _adapter app_ (`GET /test`)
3. _adapter app_ `/test` returns 401 when _request (browser)_ doesn't have valid cookie
4. _nginx_ handles 401 with `error_page`, so do internal redirection (`/_auth/initiate`)
5. _nginx_ handles `/_auth/initiate`. It will be proxied to _adapter app_ `GET /initiate`.
  - Also _nginx_ passes some information for callback to _adapter app._
  - `x-ngx-omniauth-initiate-back-to` URL to back after logged in
  - `x-ngx-omniauth-initiate-callback` URL that proxies to _adapter app_ `/callback`. This must be same domain to _backend app_ for cookie.
6. _adapter app_ `GET /initiate` redirects to `/auth/:provider`.
7. _Browser_ do some authenticate in _adapter app_ with Omniauth.
8. _adapter app's_ omniauth callback sets valid session, then redirects to `/_auth/callback`, where specified at `x-ngx-omniauth-initiate-callback`.
  - _Adapter app_ gives GET parameter named `session` on redirect. It contains encrypted session.
9. _nginx_ handles `/_auth/callback`. It will be proxied to _adapter app_ `/callback`.
  - This decrypts given encrypted session string and set to cookie.
  - Then redirect to `x-ngx-omniauth-initiate-back-to`.
10. _browser_ backs to URL where attempted to access first, at step 1.
11. _nginx_ sends auth subrequest to _backend app_ `/test`.
12. _backend app_ `/test` returns 200, because request has valid session cookie.
13. _nginx_ returns response as usual.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/sorah/nginx_omniauth_adapter.


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

