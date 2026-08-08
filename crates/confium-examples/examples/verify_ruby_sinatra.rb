# Sinatra HTTP verify endpoint using the Confium Ruby gem.
#
#   gem install sinatra confium
#   ruby verify_ruby_sinatra.rb

require 'sinatra'
require 'confium'
require 'json'

post '/verify/composite' do
  content_type :json
  body = JSON.parse(request.body.read)
  sig = Confium::Composite::Signature.from_json(body['signature'])
  result = sig.verify(body['message'].unpack1('m'))
  { valid: result.all_verified? }.to_json
end
