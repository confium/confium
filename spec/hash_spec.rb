require 'ffi'
require 'digest'

module LibConfium
  extend FFI::Library
  ffi_lib 'confium'

  attach_function :cfm_create,
                  %i[pointer],
                  :uint32
  attach_function :cfm_destroy,
                  %i[pointer],
                  :uint32
  attach_function :cfm_plugin_load,
                  %i[pointer string string pointer pointer],
                  :uint32

  attach_function :cfm_hash_create,
                  %i[pointer pointer pointer pointer pointer pointer],
                  :uint32
  attach_function :cfm_hash_output_size,
                  %i[pointer pointer],
                  :uint32
  attach_function :cfm_hash_block_size,
                  %i[pointer pointer],
                  :uint32
  attach_function :cfm_hash_update,
                  %i[pointer pointer uint32],
                  :uint32
  attach_function :cfm_hash_reset,
                  %i[pointer],
                  :uint32
  attach_function :cfm_hash_clone,
                  %i[pointer pointer],
                  :uint32
  attach_function :cfm_hash_finalize,
                  %i[pointer pointer uint32],
                  :uint32
  attach_function :cfm_hash_destroy,
                  %i[pointer],
                  :void
end

def call_ffi_rc(fn, *args)
  rc = LibConfium.method(fn).call(*args)
  raise "FFI call to #{fn} failed (rc: #{rc})" unless rc.zero?
  rc
end

def call_ffi(fn, *args)
  call_ffi_rc(fn, *args)
  nil
end

module Confium

class CFM
  attr_reader :ptr

  def initialize
    pptr = FFI::MemoryPointer.new(:pointer)
    call_ffi(:cfm_create, pptr)
    @ptr = FFI::AutoPointer.new(pptr.read_pointer, self.class.method(:destroy))
  end

  def self.destroy(ptr)
    LibConfium.cfm_destroy(ptr)
  end

  def load_plugin(name, path)
    call_ffi(:cfm_plugin_load, @ptr, name, path, nil, nil)
  end
end

class Digest < ::Digest::Class
  attr_reader :name
  attr_reader :ptr

  def initialize(cfm, name)
    @name = name
    pptr = FFI::MemoryPointer.new(:pointer)
    call_ffi(:cfm_hash_create, cfm.ptr, pptr, name, nil, nil, nil)
    ptr = pptr.read_pointer
    raise if ptr.null?
    @ptr = FFI::AutoPointer.new(ptr, self.class.method(:destroy))
  end

  def initialize_copy(source)
    @name = source.name
    pptr = FFI::MemoryPointer.new(:pointer)
    call_ffi(:cfm_hash_clone, source.ptr, pptr)
    ptr = pptr.read_pointer
    @ptr = FFI::AutoPointer.new(ptr, self.class.method(:destroy))
  end

  def self.destroy(ptr)
    LibConfium.cfm_hash_destroy(ptr)
  end

  def block_length
    plength = FFI::MemoryPointer.new(:uint32)
    call_ffi(:cfm_hash_block_size, @ptr, plength)
    plength.read(:uint32)
  end
  
  def digest_length
    plength = FFI::MemoryPointer.new(:uint32)
    call_ffi(:cfm_hash_output_size, @ptr, plength)
    plength.read(:uint32)
  end
  
  def update(data)
    call_ffi(:cfm_hash_update, @ptr, data, data.bytesize)
    self
  end

  def reset
    call_ffi(:cfm_hash_reset, @ptr)
    self
  end

  def finish
    buf = FFI::MemoryPointer.new(:uint8, digest_length)
    call_ffi(:cfm_hash_finalize, @ptr, buf, buf.size)
    buf.read_bytes(buf.size)
  end

  alias << update
end

end

describe Confium::Digest do
  let(:cfm) do
    cfm = Confium::CFM.new
    cfm.load_plugin('botan', ENV['CFM_HASH_BOTAN_PLUGIN_PATH'])
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

