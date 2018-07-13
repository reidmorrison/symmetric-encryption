$LOAD_PATH.unshift File.dirname(__FILE__) + '/../lib'

require 'yaml'
require 'minitest/autorun'
require 'minitest/stub_any_instance'
require 'awesome_print'
require 'active_record'
require 'symmetric-encryption'
require 'fileutils'

# Load Symmetric Encryption keys
SymmetricEncryption.load!(File.join(File.dirname(__FILE__), 'config', 'symmetric-encryption.yml'), 'test')
