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

Mongoid.logger = Logger.new($stdout)
filename = defined?(Mongoid::VERSION) ? "test/config/mongoid_v3.yml" : "test/config/mongoid_v2.yml"
Mongoid.load!(filename)

class MongoidUser
  include Mongoid::Document

  field :name,                             :type => String
  field :encrypted_bank_account_number,    :type => String,  :encrypted => true
  field :encrypted_social_security_number, :type => String,  :encrypted => true
  field :encrypted_string,                 :type => String,  :encrypted => {:random_iv => true}
  field :encrypted_long_string,            :type => String,  :encrypted => {:random_iv => true, :compress => true}

  #  validates :encrypted_bank_account_number, :symmetric_encrypted => true
  #  validates :encrypted_social_security_number, :symmetric_encrypted => true
end

# Load Symmetric Encryption keys
SymmetricEncryption.load!(File.join(File.dirname(__FILE__), 'config', 'symmetric-encryption.yml'), 'test')

#
# Unit Tests for field encrypted and validation aspects of SymmetricEncryption
#
class FieldEncryptedTest < Test::Unit::TestCase
  context 'the SymmetricEncryption Library' do
    setup do
      @bank_account_number = "1234567890"
      @bank_account_number_encrypted = "QEVuQwIAL94ArJeFlJrZp6SYsvoOGA=="

      @social_security_number = "987654321"
      @social_security_number_encrypted = "QEVuQwIAS+8X1NRrqdfEIQyFHVPuVA=="

      @integer = 32768
      @integer_encrypted = "FA3smFQEKqB/ITv+A0xACg=="

      @float = 0.9867
      @float_encrypted = "z7Pwt2JDp74d+u0IXFAdrQ=="

      @date = Date.parse('20120320')
      @date_encrypted = "WTkSPHo5ApSSHBJMxxWt2A=="

      @string = "A string containing some data to be encrypted with a random initialization vector"
      @long_string = "A string containing some data to be encrypted with a random initialization vector and compressed since it takes up so much space in plain text form"

      # #TODO Intercept passing in attributes to create etc.
      @user = MongoidUser.new(
        :encrypted_bank_account_number    => @bank_account_number_encrypted,
        :encrypted_social_security_number => @social_security_number_encrypted,
        :name                             => "Joe Bloggs"
      )
    end

    should "have encrypted methods" do
      assert_equal true, @user.respond_to?(:encrypted_bank_account_number)
      assert_equal true, @user.respond_to?(:encrypted_social_security_number)
      assert_equal true, @user.respond_to?(:encrypted_string)
      assert_equal true, @user.respond_to?(:encrypted_long_string)
      assert_equal false, @user.respond_to?(:encrypted_name)

      assert_equal true, @user.respond_to?(:encrypted_bank_account_number=)
      assert_equal true, @user.respond_to?(:encrypted_social_security_number=)
      assert_equal true, @user.respond_to?(:encrypted_string=)
      assert_equal true, @user.respond_to?(:encrypted_long_string=)
      assert_equal false, @user.respond_to?(:encrypted_name=)
    end

    should "have unencrypted methods" do
      assert_equal true, @user.respond_to?(:bank_account_number)
      assert_equal true, @user.respond_to?(:social_security_number)
      assert_equal true, @user.respond_to?(:string)
      assert_equal true, @user.respond_to?(:long_string)
      assert_equal true, @user.respond_to?(:name)

      assert_equal true, @user.respond_to?(:bank_account_number=)
      assert_equal true, @user.respond_to?(:social_security_number=)
      assert_equal true, @user.respond_to?(:string=)
      assert_equal true, @user.respond_to?(:long_string=)
      assert_equal true, @user.respond_to?(:name=)
    end

    should "have unencrypted values" do
      assert_equal @bank_account_number, @user.bank_account_number
      assert_equal @social_security_number, @user.social_security_number
    end

    should "have encrypted values" do
      assert_equal @bank_account_number_encrypted, @user.encrypted_bank_account_number
      assert_equal @social_security_number_encrypted, @user.encrypted_social_security_number
    end

    should "support same iv" do
      @user.social_security_number = @social_security_number
      assert first_value = @user.social_security_number
      # Assign the same value
      @user.social_security_number = @social_security_number
      assert_equal first_value, @user.social_security_number
    end

    should "support a random iv" do
      @user.string = @string
      assert first_value = @user.encrypted_string
      # Assign the same value
      @user.string = @string.dup
      assert_equal true, first_value != @user.encrypted_string
    end

    should "support a random iv and compress" do
      @user.string = @long_string
      @user.long_string = @long_string

      assert_equal true, (@user.encrypted_long_string.length.to_f / @user.encrypted_string.length) < 0.8
    end

    should "encrypt" do
      user = MongoidUser.new
      user.bank_account_number = @bank_account_number
      assert_equal @bank_account_number, user.bank_account_number
      assert_equal @bank_account_number_encrypted, user.encrypted_bank_account_number
    end

    should "all paths should lead to the same result" do
      assert_equal @bank_account_number_encrypted, (@user.encrypted_social_security_number = @bank_account_number_encrypted)
      assert_equal @bank_account_number, @user.social_security_number
    end

    should "all paths should lead to the same result 2" do
      assert_equal @bank_account_number, (@user.social_security_number = @bank_account_number)
      assert_equal @bank_account_number_encrypted, @user.encrypted_social_security_number
    end

    should "all paths should lead to the same result, check uninitialized" do
      user = MongoidUser.new
      assert_equal nil, user.social_security_number
      assert_equal @bank_account_number, (user.social_security_number = @bank_account_number)
      assert_equal @bank_account_number, user.social_security_number
      assert_equal @bank_account_number_encrypted, user.encrypted_social_security_number

      assert_equal nil, (user.social_security_number = nil)
      assert_equal nil, user.social_security_number
      assert_equal nil, user.encrypted_social_security_number
    end

    should "allow unencrypted values to be passed to the constructor" do
      user = MongoidUser.new(:bank_account_number => @bank_account_number, :social_security_number => @social_security_number)
      assert_equal @bank_account_number, user.bank_account_number
      assert_equal @social_security_number, user.social_security_number
      assert_equal @bank_account_number_encrypted, user.encrypted_bank_account_number
      assert_equal @social_security_number_encrypted, user.encrypted_social_security_number
    end

    should "allow both encrypted and unencrypted values to be passed to the constructor" do
      user = MongoidUser.new(:encrypted_bank_account_number => @bank_account_number_encrypted, :social_security_number => @social_security_number)
      assert_equal @bank_account_number, user.bank_account_number
      assert_equal @social_security_number, user.social_security_number
      assert_equal @bank_account_number_encrypted, user.encrypted_bank_account_number
      assert_equal @social_security_number_encrypted, user.encrypted_social_security_number
    end
  end

end