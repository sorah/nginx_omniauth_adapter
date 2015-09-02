require 'sinatra'
require 'json'

get '/' do
  content_type :text

  {
    provider: request.env['HTTP_X_NGX_OMNIAUTH_PROVIDER'],
    user: request.env['HTTP_X_NGX_OMNIAUTH_USER'],
    info: JSON.parse(request.env['HTTP_X_NGX_OMNIAUTH_INFO'].unpack('m*')[0]),
  }.to_json
end

get '/hello' do
  content_type :text
  'hola'
end

get '/unauthorized' do
  [401, {'Content-Type' => 'text/plain'}, '401 :(']
end
