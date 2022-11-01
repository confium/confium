require 'ffi'

module Confium
  class CFM
    attr_reader :ptr

    def initialize
      pptr = FFI::MemoryPointer.new(:pointer)
      Confium.call_ffi(:cfm_create, pptr)
      @ptr = FFI::AutoPointer.new(pptr.read_pointer, self.class.method(:destroy))

      load_plugin('botan', ENV['CFM_HASH_BOTAN_PLUGIN_PATH'])
    end

    def self.destroy(ptr)
      Confium::Lib.cfm_destroy(ptr)
    end

    def load_plugin(name, path)
      Confium.call_ffi(:cfm_plugin_load, @ptr, name, path, nil, nil)
    end

  end
end
