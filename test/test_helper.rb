# Allow examples to be run in-place without requiring a gem install
$LOAD_PATH.unshift File.dirname(__FILE__) + '/../lib'

require 'yaml'
require 'minitest/autorun'
require 'semantic_logger'
# Since we want both the AR and Mongoid extensions loaded we need to require them first
require 'active_record'
require 'symmetric-encryption'
require 'awesome_print'

begin
  require 'active_model/serializers'
rescue LoadError
  # Only used when running Rails 5 and MongoMapper
end

SemanticLogger.add_appender(file_name: 'test.log', formatter: :color)
SemanticLogger.default_level = :trace

# Load Symmetric Encryption keys
SymmetricEncryption.load!(File.join(File.dirname(__FILE__), 'config', 'symmetric-encryption.yml'), 'test')
