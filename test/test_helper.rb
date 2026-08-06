$LOAD_PATH.unshift "#{File.dirname(__FILE__)}/../lib"

# Must be started before any application code is required so that all lib files are tracked.
# Enable by running the suite with COVERAGE=true (off by default to keep normal runs fast).
if ENV["COVERAGE"]
  require "simplecov"
  SimpleCov.start do
    command_name "Minitest"
    add_filter "/test/"
    track_files "lib/**/*.rb"

    add_group "Keystores", "lib/symmetric_encryption/keystore"
    add_group "ActiveRecord", "lib/symmetric_encryption/active_record"
    add_group "Railties", "lib/symmetric_encryption/railties"
    add_group "Utils", "lib/symmetric_encryption/utils"
  end
end

require "yaml"
require "minitest/autorun"
require "minitest/stub_any_instance"
require "amazing_print"
require "active_record"
require "symmetric-encryption"
require "fileutils"

# Ensure the test keys have the correct permissions (0600) since git
# can't keep track of this (it sets them to 0644)
%w[test_new.key test_secondary_1.key].each do |key|
  FileUtils.chmod 0o600, File.join(File.dirname(__FILE__), "config", key)
end

# Load Symmetric Encryption keys
SymmetricEncryption.load!(File.join(File.dirname(__FILE__), "config", "symmetric-encryption.yml"), "test")
