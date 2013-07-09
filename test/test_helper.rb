# Allow examples to be run in-place without requiring a gem install
$LOAD_PATH.unshift File.dirname(__FILE__) + '/../lib'

require 'rubygems'
require 'logger'
require 'erb'
require 'test/unit'
require 'shoulda'
# Since we want both the Mongoid extensions loaded we need to require it first
require 'active_record'
require 'mongoid'
require 'symmetric-encryption'
require 'symmetric_encryption/extensions/mongoid/fields'

# Load Symmetric Encryption keys
SymmetricEncryption.load!(File.join(File.dirname(__FILE__), 'config', 'symmetric-encryption.yml'), 'test')
