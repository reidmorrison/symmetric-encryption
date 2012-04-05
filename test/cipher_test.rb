# Allow examples to be run in-place without requiring a gem install
$LOAD_PATH.unshift File.dirname(__FILE__) + '/../lib'

require 'rubygems'
require 'test/unit'
require 'shoulda'
require 'symmetric_encryption/cipher'

# Unit Test for SymmetricEncryption::Cipher
#
class CipherTest < Test::Unit::TestCase
  context 'standalone' do

    should "allow setting the cipher" do
      cipher = SymmetricEncryption::Cipher.new(
        :cipher => 'aes-128-cbc',
        :key => '1234567890ABCDEF1234567890ABCDEF',
        :iv  => '1234567890ABCDEF'
      )
      assert_equal 'aes-128-cbc', cipher.cipher
    end

    should "not require an iv" do
      cipher = SymmetricEncryption::Cipher.new(
        :key => '1234567890ABCDEF1234567890ABCDEF'
      )
      assert_equal "\302<\351\227oj\372\3331\310\260V\001\v'\346", cipher.encrypt('Hello World')
    end

    should "throw an exception on bad data" do
      cipher = SymmetricEncryption::Cipher.new(
        :cipher => 'aes-128-cbc',
        :key => '1234567890ABCDEF1234567890ABCDEF',
        :iv  => '1234567890ABCDEF'
      )
      assert_raise OpenSSL::Cipher::CipherError do
        cipher.decrypt('bad data')
      end
    end

  end

  context 'with configuration' do
    setup do
      @cipher = SymmetricEncryption::Cipher.new(
        :key => '1234567890ABCDEF1234567890ABCDEF',
        :iv  => '1234567890ABCDEF'
      )
      @social_security_number = "987654321"
      @social_security_number_encrypted = "A\335*\314\336\250V\340\023%\000S\177\305\372\266"
      @sample_data = [
        { :text => '555052345', :encrypted => ''}
      ]
    end

    should "default to 'aes-256-cbc'" do
      assert_equal 'aes-256-cbc', @cipher.cipher
    end

    should "encrypt simple string" do
      assert_equal @social_security_number_encrypted, @cipher.encrypt(@social_security_number)
    end

    should "decrypt string" do
      assert_equal @social_security_number, @cipher.decrypt(@social_security_number_encrypted)
    end

  end
end