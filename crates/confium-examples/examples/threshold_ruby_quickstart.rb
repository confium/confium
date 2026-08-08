# Confium CMP20 DKG + sign in Ruby.
#
#   gem install confium
#   ruby threshold_ruby_quickstart.rb

require 'confium'

# DKG: 2-of-3 threshold key
kg = Confium::TC::Cmp20.keygen(threshold: 2, parties: 3)
puts "Public key: #{kg.public_key.bytesize} bytes"
puts "Shares: #{kg.shares.length}"

# Sign with threshold shares
sig = Confium::TC::Cmp20.sign(kg.shares, threshold: 2, message: "hello, threshold world")
puts "Signature: #{sig.bytesize} bytes"
puts "✅ Done"
