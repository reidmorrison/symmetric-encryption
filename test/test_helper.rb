$LOAD_PATH.unshift File.dirname(__FILE__) + '/../lib'

require 'yaml'
require 'minitest/autorun'
require 'minitest/stub_any_instance'
require 'awesome_print'
require 'active_record'
require 'symmetric-encryption'
require 'fileutils'

# Ensure the test keys have the correct permissions (0600) since git
# can't keep track of this (it sets them to 0644)
%w[test_new.key test_secondary_1.key].each do |key|
  FileUtils.chmod 0o600, File.join(File.dirname(__FILE__), 'config', key)
end

# Load Symmetric Encryption keys
SymmetricEncryption.load!(File.join(File.dirname(__FILE__), 'config', 'symmetric-encryption.yml'), 'test')
