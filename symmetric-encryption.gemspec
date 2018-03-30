$LOAD_PATH.push File.expand_path('lib', __dir__)

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
  s.summary               = 'Encrypt ActiveRecord and Mongoid attributes, files and passwords in configuration files.'
  s.files                 = Dir['{lib,examples}/**/*', 'LICENSE.txt', 'Rakefile', 'README.md']
  s.test_files            = Dir['test/**/*']
  s.license               = 'Apache-2.0'
  s.required_ruby_version = '>= 2.3'
  s.bindir                = 'bin'
  s.executables           = ['symmetric-encryption']
  s.add_dependency 'coercible', '~> 1.0'
end
