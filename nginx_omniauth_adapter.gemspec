# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'nginx_omniauth_adapter/version'

Gem::Specification.new do |spec|
  spec.name          = "nginx_omniauth_adapter"
  spec.version       = NginxOmniauthAdapter::VERSION
  spec.authors       = ["Shota Fukumori (sora_h)"]
  spec.email         = ["her@sorah.jp"]

  spec.summary       = %q{omniauth adapter for ngx_http_auth_request_module}
  spec.homepage      = "https://github.com/sorah/nginx_omniauth_adapter"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "bin"
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "sinatra"
  spec.add_dependency "omniauth", '< 2'

  spec.add_development_dependency "bundler"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "rspec"
  spec.add_development_dependency "rack-test"
  spec.add_development_dependency "mechanize"
end
