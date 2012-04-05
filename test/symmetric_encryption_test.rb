# Allow examples to be run in-place without requiring a gem install
$LOAD_PATH.unshift File.dirname(__FILE__) + '/../lib'

require 'rubygems'
require 'test/unit'
require 'shoulda'
require 'symmetric-encryption'

# Load Symmetric Encryption keys
SymmetricEncryption.load!(File.join(File.dirname(__FILE__), 'config', 'symmetric-encryption.yml'), 'test')

# Unit Test for SymmetricEncryption
#
class SymmetricEncryptionTest < Test::Unit::TestCase
  context 'initialized' do

    context 'SymmetricEncryption configuration' do
      setup do
        @config = SymmetricEncryption.send(:read_config, File.join(File.dirname(__FILE__), 'config', 'symmetric-encryption.yml'), 'test')
      end

      should "match config file" do
        assert_equal @config[:ciphers][0][:cipher], SymmetricEncryption.cipher.cipher
      end
    end

    context 'SymmetricEncryption tests' do
      setup do
        @social_security_number = "987654321"
        @social_security_number_encrypted = "S+8X1NRrqdfEIQyFHVPuVA==\n"
        @social_security_number_encrypted_with_secondary_1 = "D1UCu38pqJ3jc0GvwJHiow==\n"
      end

      should "encrypt simple string" do
        assert_equal @social_security_number_encrypted, SymmetricEncryption.encrypt(@social_security_number)
      end

      should "decrypt string" do
        assert_equal @social_security_number, SymmetricEncryption.decrypt(@social_security_number_encrypted)
      end

      should "determine if string is encrypted" do
        assert_equal true, SymmetricEncryption.encrypted?(@social_security_number_encrypted)
        assert_equal false, SymmetricEncryption.encrypted?(@social_security_number)
      end

      should "decrypt with secondary key when first one fails" do
        assert_equal @social_security_number, SymmetricEncryption.decrypt(@social_security_number_encrypted)
      end
    end
  end

end
