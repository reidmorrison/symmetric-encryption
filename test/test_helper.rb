# Allow examples to be run in-place without requiring a gem install
$LOAD_PATH.unshift File.dirname(__FILE__) + '/../lib'

require 'yaml'
require 'minitest/autorun'
require 'minitest/reporters'
require 'minitest/stub_any_instance'
require 'shoulda/context'
require 'semantic_logger'
# Since we want both the AR and Mongoid extensions loaded we need to require them first
require 'active_record'
require 'symmetric-encryption'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

SemanticLogger.add_appender('test.log', &SemanticLogger::Appender::Base.colorized_formatter)
SemanticLogger.default_level = :trace

# Load Symmetric Encryption keys
SymmetricEncryption.load!(File.join(File.dirname(__FILE__), 'config', 'symmetric-encryption.yml'), 'test')
