# frozen_string_literal: true

require_relative "lib/confium/version"

Gem::Specification.new do |spec|
  spec.name = "confium"
  spec.version = Confium::VERSION
  spec.authors = ["Ribose Open"]
  spec.email = ["open.source@ribose.com"]

  spec.summary = "FFI bindings for Confium."
  # spec.description = "TODO: Write a longer description or delete this line."
  spec.homepage = "https://www.confium.org"
  spec.required_ruby_version = ">= 2.6.0"

  # spec.metadata["allowed_push_host"] = "TODO: Set to your gem server 'https://example.com'"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/confium/confium"
  spec.metadata["changelog_uri"] = "https://github.com/confium/confium"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) || f.match(%r{\A(?:(?:bin|test|spec|features)/|\.(?:git|travis|circleci)|appveyor)})
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "ffi"
  spec.add_development_dependency "rspec"
end
