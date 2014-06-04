# Allow examples to be run in-place without requiring a gem install
$LOAD_PATH.unshift File.dirname(__FILE__) + '/../lib'

require 'rubygems'
require 'semantic_logger'
require 'erb'
require 'test/unit'
# Since we want both the AR and Mongoid extensions loaded we need to require them first
require 'active_record'
require 'symmetric-encryption'
# Should redefines Proc#bind so must include after Rails
require 'shoulda'

SemanticLogger.add_appender('test.log') if SemanticLogger.appenders.size == 0
SemanticLogger.default_level = :trace

# Load Symmetric Encryption keys
SymmetricEncryption.load!(File.join(File.dirname(__FILE__), 'config', 'symmetric-encryption.yml'), 'test')
