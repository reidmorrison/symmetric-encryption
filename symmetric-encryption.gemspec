$:.push File.expand_path('../lib', __FILE__)

# Maintain your gem's version:
require 'symmetric_encryption/version'

# Describe your gem and declare its dependencies:
Gem::Specification.new do |s|
  s.name                  = 'symmetric-encryption'
  s.version               = SymmetricEncryption::VERSION
  s.platform              = Gem::Platform::RUBY
  s.authors               = ['Reid Morrison']
  s.email                 = ['reidmo@gmail.com']
  s.homepage              = 'http://rocketjob.github.io/symmetric-encryption/'
  s.summary               = 'Encryption for Ruby, and Ruby on Rails'
  s.description           = 'Transparently encrypt ActiveRecord, Mongoid, and MongoMapper attributes. Encrypt passwords in configuration files. Encrypt entire files at rest.'
  s.files                 = Dir['{lib,examples}/**/*', 'LICENSE.txt', 'Rakefile', 'README.md']
  s.test_files            = Dir['test/**/*']
  s.license               = 'Apache-2.0'
  s.required_ruby_version = '>= 2.1'
  s.bindir                = 'bin'
  s.executables           = ['symmetric-encryption']
  s.add_dependency 'coercible', '~> 1.0'
end
