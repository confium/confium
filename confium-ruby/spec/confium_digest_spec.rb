# frozen_string_literal: true

require_relative "spec_helper"

# RSpec.describe Confium do
#   it "has a version number" do
#     expect(Confium::VERSION).not_to be nil
#   end
# end

RSpec.describe Confium::Digest do
  let(:cfm) do
    cfm = Confium::CFM.new
    # cfm.load_plugin('botan', ENV['CFM_HASH_BOTAN_PLUGIN_PATH'])
    cfm
  end

  let (:digest) { Confium::Digest.new(cfm, 'MD5') }

  context 'MD5' do
    it 'has the correct block length' do
      expect(digest.block_length).to be 64
    end

    it 'has the correct output length' do
      expect(digest.digest_length).to be 16
    end

    it 'produces the correct digest (no input)' do
      expect(digest.finish).to eql ['d41d8cd98f00b204e9800998ecf8427e'].pack('H*')
    end

    it 'produces the correct digest' do
      digest << 'test'
      expect(digest.finish).to eql ['098f6bcd4621d373cade4e832627b4f6'].pack('H*')
    end

    it 'can be reset' do
      digest << 'somedata'
      digest.reset
      expect(digest.finish).to eql ['d41d8cd98f00b204e9800998ecf8427e'].pack('H*')
    end

    it 'can be cloned' do
      digest << 'test'
      digest2 = digest.clone
      expect(digest.finish).to eql ['098f6bcd4621d373cade4e832627b4f6'].pack('H*')
      expect(digest2.finish).to eql ['098f6bcd4621d373cade4e832627b4f6'].pack('H*')
    end
  end

end
