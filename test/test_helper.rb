# Allow examples to be run in-place without requiring a gem install
$LOAD_PATH.unshift File.dirname(__FILE__) + '/../lib'

require 'yaml'
require 'minitest/autorun'
require 'active_record'
require 'symmetric-encryption'
require 'awesome_print'
require 'mocha/mini_test'

begin
  require 'active_model/serializers'
rescue LoadError
  # Only used when running Rails 5 and MongoMapper
end

# Load Symmetric Encryption keys
SymmetricEncryption.load!(File.join(File.dirname(__FILE__), 'config', 'symmetric-encryption.yml'), 'test')
