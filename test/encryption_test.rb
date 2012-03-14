# Allow examples to be run in-place without requiring a gem install
$LOAD_PATH.unshift File.dirname(__FILE__) + '/../lib'

require 'rubygems'
require 'test/unit'
require 'shoulda'

# Unit Test for Symmetric::Encryption
#
class EncryptionTest < Test::Unit::TestCase
  context 'initialized' do

    setup do
      Symmetric::Encryption.load!(File.join(File.dirname(__FILE__), 'config', 'symmetric-encryption.yml'), 'test')
    end

    context 'Symmetric::Encryption tests' do
      setup do
        @bank_account_number = "1234567890"
        @bank_account_number_encrypted = "QUxoUU8O/mi0o9ykgXNBFg==\n"

        @social_security_number = "987654321"
        @social_security_number_encrypted = "Jj7dKb3B0aUCnqH/YKGvKw==\n"
      end

      should "encrypt simple string" do
        assert_equal @social_security_number_encrypted, Symmetric::Encryption.encrypt(@social_security_number)
      end

      should "decrypt string" do
        assert_equal @social_security_number, Symmetric::Encryption.decrypt(@social_security_number_encrypted)
      end

      should "determine if string is encrypted" do
        assert_equal true, Symmetric::Encryption.encrypted?(@social_security_number_encrypted)
        assert_equal false, Symmetric::Encryption.encrypted?(@social_security_number)
      end
    end
  end

end
