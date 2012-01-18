# Allow examples to be run in-place without requiring a gem install
$LOAD_PATH.unshift File.dirname(__FILE__) + '/../lib'

require 'rubygems'
require 'test/unit'
require 'shoulda'
require 'symmetric-encryption'
require 'yaml'

# #TODO Need to supply the model and migrations for this test
class User
  attr_encrypted :bank_account_number
  attr_encrypted :social_security_number
end

# Unit Test for Symmetric::Encryption
#
class EncryptionTest <  ActiveSupport::TestCase
  context 'the Symmetric::Encryption Library' do

    setup do
      @bank_account_number = "1234567890"
      @bank_account_number_encrypted = "V8Dg6zeeIpDg4+qrn2mjlA==\n"

      @social_security_number = "987654321"
      @social_security_number_encrypted = "Qd0qzN6oVuATJQBTf8X6tg==\n"

      @user = User.new(
        # Encrypted Attribute
        :bank_account_number              => @bank_account_number,
        # Encrypted Attribute
        :social_security_number           => @social_security_number
      )
    end

    should "encrypt simple string" do
      assert_equal @social_security_number_encrypted, Symmetric::Encryption.encrypt(@social_security_number)
    end

    should "decrypt string" do
      assert_equal @social_security_number, Symmetric::Encryption.decrypt(@social_security_number_encrypted)
    end

    should "have encrypted methods" do
      assert_equal true, @user.respond_to?(:encrypted_bank_account_number)
      assert_equal true, @user.respond_to?(:encrypted_social_security_number)
      assert_equal false, @user.respond_to?(:encrypted_name)
    end

    should "have unencrypted values" do
      assert_equal @bank_account_number, @user.bank_account_number
      assert_equal @social_security_number, @user.social_security_number
    end

    should "have encrypted values" do
      assert_equal @bank_account_number_encrypted, @user.encrypted_bank_account_number
      assert_equal @social_security_number_encrypted, @user.encrypted_social_security_number
    end

    should "encrypt" do
      user = User.new
      user.bank_account_number = @bank_account_number
      assert_equal @bank_account_number, user.bank_account_number
      assert_equal @bank_account_number_encrypted, user.encrypted_bank_account_number
    end

    should "allow lookups using unencrypted or encrypted column name" do
      user_id = @user.save!

      inq = User.find_by_bank_account_number(@bank_account_number)
      assert_equal @bank_account_number, inq.bank_account_number
      assert_equal @bank_account_number_encrypted, inq.encrypted_bank_account_number

      User.delete(user_id)
    end

    should "return encrypted attributes for the class" do
      expect = {:social_security_number=>:encrypted_social_security_number, :bank_account_number=>:encrypted_bank_account_number, :check_bank_account_number=>:encrypted_check_bank_account_number}
      result = User.encrypted_attributes
      expect.each_pair {|k,v| assert_equal expect[k], result[k]}
    end

    should "return encrypted keys for the class" do
      expect = [:social_security_number, :bank_account_number, :check_bank_account_number]
      result = User.encrypted_keys
      expect.each {|val| assert_equal true, result.include?(val)}

      # Also check encrypted_attribute?
      expect.each {|val| assert_equal true, User.encrypted_attribute?(val)}
    end

    should "return encrypted columns for the class" do
      expect = [:encrypted_social_security_number, :encrypted_bank_account_number, :encrypted_check_bank_account_number]
      result = User.encrypted_columns
      expect.each {|val| assert_equal true, result.include?(val)}

      # Also check encrypted_column?
      expect.each {|val| assert_equal true, User.encrypted_column?(val)}
    end

  end
end
