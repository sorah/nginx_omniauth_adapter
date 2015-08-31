$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'nginx_omniauth_adapter'

ENV['RACK_ENV'] = 'test'
