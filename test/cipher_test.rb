# Allow examples to be run in-place without requiring a gem install
$LOAD_PATH.unshift File.dirname(__FILE__) + '/../lib'

require 'rubygems'
require 'test/unit'
require 'shoulda'
require 'symmetric/cipher'

# Unit Test for Symmetric::Cipher
#
class CipherTest < Test::Unit::TestCase
  context 'standalone' do

    should "allow setting the cipher" do
      cipher = Symmetric::Cipher.new(
        :cipher => 'aes-128-cbc',
        :key => '1234567890ABCDEF1234567890ABCDEF',
        :iv  => '1234567890ABCDEF'
      )
      assert_equal 'aes-128-cbc', cipher.cipher
    end

    should "not require an iv" do
      cipher = Symmetric::Cipher.new(
        :key => '1234567890ABCDEF1234567890ABCDEF'
      )
      assert_equal "wjzpl29q+tsxyLBWAQsn5g==\n", cipher.encrypt('Hello World')
    end

    should "throw an exception on bad data" do
      cipher = Symmetric::Cipher.new(
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
      @cipher = Symmetric::Cipher.new(
        :key => '1234567890ABCDEF1234567890ABCDEF',
        :iv  => '1234567890ABCDEF'
      )
      @social_security_number = "987654321"
      @social_security_number_encrypted = "Qd0qzN6oVuATJQBTf8X6tg==\n"
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

    should "determine if string is encrypted" do
      assert_equal true, @cipher.encrypted?(@social_security_number_encrypted)
      assert_equal false, @cipher.encrypted?(@social_security_number)
    end

  end
end