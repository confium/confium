# frozen_string_literal: true

require_relative "confium/version"

module Confium
  # class Error < StandardError; end

  # def self.context
  #   cfm = Confium::CFM.new
  #   cfm.load_plugin('botan', ENV['CFM_HASH_BOTAN_PLUGIN_PATH'])
  #   cfm
  # end

  def self.call_ffi_rc(fn, *args)
    rc = Confium::Lib.method(fn).call(*args)
    raise "FFI call to #{fn} failed (rc: #{rc})" unless rc.zero?
    rc
  end

  def self.call_ffi(fn, *args)
    call_ffi_rc(fn, *args)
    nil
  end

end

require_relative 'confium/lib'
require_relative 'confium/cfm'
require_relative 'confium/digest'
