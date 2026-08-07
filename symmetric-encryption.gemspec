lib = File.expand_path("lib", __dir__)
$LOAD_PATH.unshift lib unless $LOAD_PATH.include?(lib)

# Maintain your gem's version:
require "symmetric_encryption/version"

# Describe your gem and declare its dependencies:
Gem::Specification.new do |s|
  s.name                  = "symmetric-encryption"
  s.version               = SymmetricEncryption::VERSION
  s.platform              = Gem::Platform::RUBY
  s.authors               = ["Reid Morrison"]
  s.homepage              = "https://encryption.reidmorrison.com"
  s.summary               = "Encrypt ActiveRecord and Mongoid attributes, files and passwords in configuration files."
  s.description           = "Symmetric Encryption uses OpenSSL to transparently encrypt and decrypt ActiveRecord " \
                            "attributes, Mongoid fields, passwords in configuration files, and entire files at rest. " \
                            "Encryption keys are held in a keystore, outside of the source code, and support key " \
                            "rotation without downtime."
  s.files                 = Dir["lib/**/*", "bin/*", "docs/*.md", "LICENSE.txt", "Rakefile", "README.md"]
  s.license               = "Apache-2.0"
  s.required_ruby_version = ">= 3.2"
  s.bindir                = "bin"
  s.executables           = ["symmetric-encryption"]
  s.add_dependency "coercible", "~> 1.0"
  s.metadata = {
    "bug_tracker_uri"       => "https://github.com/reidmorrison/symmetric-encryption/issues",
    "changelog_uri"         => "https://github.com/reidmorrison/symmetric-encryption/blob/main/CHANGELOG.md",
    "documentation_uri"     => "https://encryption.reidmorrison.com",
    "source_code_uri"       => "https://github.com/reidmorrison/symmetric-encryption/tree/v#{SymmetricEncryption::VERSION}",
    "rubygems_mfa_required" => "true"
  }
end
