require 'ffi'

module Confium
  module Lib
    # FFI load pattern taken from: ffi-geos
    # https://github.com/dark-panda/ffi-geos/blob/master/lib/ffi-geos.rb
    extend FFI::Library

    def self.search_paths
      @search_paths ||= \
        if ENV['CONFIUM_LIBRARY_PATH']
          [ENV['CONFIUM_LIBRARY_PATH']]
        elsif FFI::Platform::IS_WINDOWS
          ENV['PATH'].split(File::PATH_SEPARATOR)
        else
          [
            '/usr/local/{lib64,lib}',
            '/opt/local/{lib64,lib}',
            '/usr/{lib64,lib}',
            '/opt/homebrew/lib',
            '/usr/lib/{x86_64,i386,aarch64}-linux-gnu'
          ]
        end
    end

    def self.find_lib(lib)
      if ENV['CONFIUM_LIBRARY_PATH'] && File.file?(ENV['CONFIUM_LIBRARY_PATH'])
        ENV['CONFIUM_LIBRARY_PATH']
      else
        Dir.glob(search_paths.map do |path|
          File.expand_path(File.join(path, "#{lib}.#{FFI::Platform::LIBSUFFIX}{,.?}"))
        end).first
      end
    end

    def self.confium_library_path
      @confium_library_path ||= \
        # On MingW the libraries have version numbers
        find_lib('{lib,}confium{,-?}')
    end

    extend ::FFI::Library

    FFI_LAYOUT = {
      cfm_create: [ %i[pointer], :uint32 ],
      cfm_destroy: [ %i[pointer], :uint32 ],
      cfm_plugin_load: [ %i[pointer string string pointer pointer], :uint32 ],
      cfm_hash_create: [ %i[pointer pointer pointer pointer pointer pointer], :uint32 ],
      cfm_hash_output_size: [ %i[pointer pointer], :uint32 ],
      cfm_hash_block_size: [ %i[pointer pointer], :uint32 ],
      cfm_hash_update: [ %i[pointer pointer uint32], :uint32 ],
      cfm_hash_reset: [ %i[pointer], :uint32 ],
      cfm_hash_clone: [ %i[pointer pointer], :uint32 ],
      cfm_hash_finalize: [ %i[pointer pointer uint32], :uint32 ],
      cfm_hash_destroy: [ %i[pointer], :void ],
    }.freeze

    ffi_lib(confium_library_path)

    FFI_LAYOUT.each do |func, ary|
      begin
        class_eval do
          attach_function(func, ary.first, ary.last)
        end
      rescue FFI::NotFoundError
        # that's okay
      end
    end

  end
end
