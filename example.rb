require 'ffi'

module LibConfium
  extend FFI::Library
  ffi_lib 'confium'

  attach_function :cfm_create,
                  %i[pointer],
                  :uint32
  attach_function :cfm_destroy,
                  %i[pointer],
                  :uint32
  attach_function :cfm_hash_create,
                  %i[string pointer],
                  :uint32
  attach_function :cfm_hash_destroy,
                  %i[pointer],
                  :uint32
  attach_function :cfm_load_plugin,
                  %i[pointer string],
                  :uint32
end

pptr = FFI::MemoryPointer.new(:pointer)
LibConfium.cfm_create(pptr)
lib = pptr.read_pointer

LibConfium.cfm_load_plugin(lib, 'libhash_botan.dylib')

LibConfium.cfm_hash_create('SHA256', pptr)
hash = pptr.read_pointer
LibConfium.cfm_hash_destroy(hash)

LibConfium.cfm_destroy(lib)

