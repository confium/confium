require 'ffi'
require 'digest'

module Confium
  class Digest < ::Digest::Class
    attr_reader :name
    attr_reader :ptr

    def initialize(cfm, name)
      @name = name
      pptr = FFI::MemoryPointer.new(:pointer)
      Confium.call_ffi(:cfm_hash_create, cfm.ptr, pptr, name, nil, nil, nil)
      ptr = pptr.read_pointer
      raise if ptr.null?
      @ptr = FFI::AutoPointer.new(ptr, self.class.method(:destroy))
    end

    def initialize_copy(source)
      @name = source.name
      pptr = FFI::MemoryPointer.new(:pointer)
      Confium.call_ffi(:cfm_hash_clone, source.ptr, pptr)
      ptr = pptr.read_pointer
      @ptr = FFI::AutoPointer.new(ptr, self.class.method(:destroy))
    end

    def self.destroy(ptr)
      Confium::Lib.cfm_hash_destroy(ptr)
    end

    def block_length
      plength = FFI::MemoryPointer.new(:uint32)
      Confium.call_ffi(:cfm_hash_block_size, @ptr, plength)
      plength.read(:uint32)
    end

    def digest_length
      plength = FFI::MemoryPointer.new(:uint32)
      Confium.call_ffi(:cfm_hash_output_size, @ptr, plength)
      plength.read(:uint32)
    end

    def update(data)
      Confium.call_ffi(:cfm_hash_update, @ptr, data, data.bytesize)
      self
    end

    def reset
      Confium.call_ffi(:cfm_hash_reset, @ptr)
      self
    end

    def finish
      buf = FFI::MemoryPointer.new(:uint8, digest_length)
      Confium.call_ffi(:cfm_hash_finalize, @ptr, buf, buf.size)
      buf.read_bytes(buf.size)
    end

    alias << update
  end
end
