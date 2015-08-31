require "nginx_omniauth_adapter/version"
require "nginx_omniauth_adapter/app"

module NginxOmniauthAdapter
  def self.app(*args)
    App.rack *args
  end
end
