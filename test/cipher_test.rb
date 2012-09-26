# Allow examples to be run in-place without requiring a gem install
$LOAD_PATH.unshift File.dirname(__FILE__) + '/../lib'

require 'rubygems'
require 'test/unit'
require 'shoulda'
require 'symmetric_encryption'

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
      result = "\302<\351\227oj\372\3331\310\260V\001\v'\346"
      # Note: This test fails on JRuby 1.7 RC1 since it's OpenSSL
      #       behaves differently when no IV is supplied.
      #       It instead encrypts to the following value:
      # result = "0h\x92\x88\xA1\xFE\x8D\xF5\xF3v\x82\xAF(P\x83Y"
      result.force_encoding('binary') if defined?(Encoding)
      assert_equal result, cipher.encrypt('Hello World')
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
      @social_security_number_encrypted.force_encoding('binary') if defined?(Encoding)

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

    if defined?(Encoding)
      context "on Ruby 1.9" do
        should "encode encrypted data as binary" do
          assert_equal Encoding.find('binary'), @cipher.encrypt(@social_security_number).encoding
        end

        should "decode encrypted data as utf-8" do
          assert_equal Encoding.find('utf-8'), @cipher.decrypt(@cipher.encrypt(@social_security_number)).encoding
        end
      end
    end

  end
end