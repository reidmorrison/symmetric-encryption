# Allow examples to be run in-place without requiring a gem install
$LOAD_PATH.unshift File.dirname(__FILE__) + '/../lib'

require 'rubygems'
require 'test/unit'
require 'shoulda'
require 'symmetric_encryption'

# Load Symmetric Encryption keys
SymmetricEncryption.load!(File.join(File.dirname(__FILE__), 'config', 'symmetric-encryption.yml'), 'test')

# Unit Test for SymmetricEncryption::Cipher
#
class CipherTest < Test::Unit::TestCase
  context 'standalone' do

    should "allow setting the cipher_name" do
      cipher = SymmetricEncryption::Cipher.new(
        :cipher_name   => 'aes-128-cbc',
        :key      => '1234567890ABCDEF1234567890ABCDEF',
        :iv       => '1234567890ABCDEF',
        :encoding => :none
      )
      assert_equal 'aes-128-cbc', cipher.cipher_name
    end

    should "not require an iv" do
      cipher = SymmetricEncryption::Cipher.new(
        :key      => '1234567890ABCDEF1234567890ABCDEF',
        :encoding => :none
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
        :cipher_name   => 'aes-128-cbc',
        :key      => '1234567890ABCDEF1234567890ABCDEF',
        :iv       => '1234567890ABCDEF',
        :encoding => :none
      )
      assert_raise OpenSSL::Cipher::CipherError do
        cipher.decrypt('bad data')
      end
    end

  end

  [false, true].each do |always_add_header|
    SymmetricEncryption::Cipher::ENCODINGS.each do |encoding|
      context "encoding: #{encoding} with#{'out' unless always_add_header} header" do
        setup do
          @social_security_number = "987654321"
          @social_security_number_encrypted =
            case encoding
          when :base64
            always_add_header ? "QEVuQwAAyTeLjsHTa8ykoO95K0KQmg==\n" : "yTeLjsHTa8ykoO95K0KQmg==\n"
          when :base64strict
            always_add_header ? "QEVuQwAAyTeLjsHTa8ykoO95K0KQmg==" : "yTeLjsHTa8ykoO95K0KQmg=="
          when :base16
            always_add_header ? "40456e430000c9378b8ec1d36bcca4a0ef792b42909a" : "c9378b8ec1d36bcca4a0ef792b42909a"
          when :none
            bin = always_add_header ? "@EnC\x00\x00\xC97\x8B\x8E\xC1\xD3k\xCC\xA4\xA0\xEFy+B\x90\x9A" : "\xC97\x8B\x8E\xC1\xD3k\xCC\xA4\xA0\xEFy+B\x90\x9A"
            bin.force_encoding(Encoding.find("binary"))
          else
            raise "Add test for encoding: #{encoding}"
          end
          @social_security_number_encrypted_with_secondary_1 = "D1UCu38pqJ3jc0GvwJHiow==\n"
          @non_utf8 = "\xc2".force_encoding('binary')
          @cipher = SymmetricEncryption::Cipher.new(
            key:               'ABCDEF1234567890ABCDEF1234567890',
            iv:                'ABCDEF1234567890',
            cipher_name:       'aes-128-cbc',
            encoding:          encoding,
            always_add_header: always_add_header
          )
        end

        should "encrypt simple string" do
          assert_equal @social_security_number_encrypted, @cipher.encrypt(@social_security_number)
        end

        should "decrypt string" do
          assert decrypted = @cipher.decrypt(@social_security_number_encrypted)
          assert_equal @social_security_number, decrypted
          assert_equal Encoding.find('utf-8'), decrypted.encoding, decrypted
        end

        should 'return BINARY encoding for non-UTF-8 encrypted data' do
          assert_equal Encoding.find('binary'), @non_utf8.encoding
          assert_equal true, @non_utf8.valid_encoding?
          assert encrypted = @cipher.encrypt(@non_utf8)
          assert decrypted = @cipher.decrypt(encrypted)
          assert_equal true, decrypted.valid_encoding?
          assert_equal Encoding.find('binary'), decrypted.encoding, decrypted
          assert_equal @non_utf8, decrypted
        end

        should "return nil when encrypting nil" do
          assert_equal nil, @cipher.encrypt(nil)
        end

        should "return '' when encrypting ''" do
          assert_equal '', @cipher.encrypt('')
        end

        should "return nil when decrypting nil" do
          assert_equal nil, @cipher.decrypt(nil)
        end

        should "return '' when decrypting ''" do
          assert_equal '', @cipher.decrypt('')
        end
      end
    end
  end

  context 'with configuration' do
    setup do
      @cipher = SymmetricEncryption::Cipher.new(
        :key               => '1234567890ABCDEF1234567890ABCDEF',
        :iv                => '1234567890ABCDEF',
        :encoding          => :none
      )
      @social_security_number = "987654321"

      @social_security_number_encrypted = "A\335*\314\336\250V\340\023%\000S\177\305\372\266"
      @social_security_number_encrypted.force_encoding('binary') if defined?(Encoding)

      @sample_data = [
        { :text => '555052345', :encrypted => ''}
      ]
    end

    should "default to 'aes-256-cbc'" do
      assert_equal 'aes-256-cbc', @cipher.cipher_name
    end

    context "with header" do
      setup do
        @social_security_number = "987654321"
      end

      should "build and parse header" do
        assert random_key_pair = SymmetricEncryption::Cipher.random_key_pair('aes-128-cbc')
        assert binary_header = SymmetricEncryption::Cipher.build_header(SymmetricEncryption.cipher.version, compressed=true, random_key_pair[:iv], random_key_pair[:key], random_key_pair[:cipher_name])
        header = SymmetricEncryption::Cipher.parse_header!(binary_header)
        assert_equal true, header.compressed
        assert random_cipher = SymmetricEncryption::Cipher.new(random_key_pair)
        assert_equal random_cipher.cipher_name, header.cipher_name, "Ciphers differ"
        assert_equal random_cipher.send(:key), header.key, "Keys differ"
        assert_equal random_cipher.send(:iv), header.iv, "IVs differ"

        string = "Hello World"
        cipher = SymmetricEncryption::Cipher.new(:key => header.key, :iv => header.iv, :cipher_name => header.cipher_name)
        # Test Encryption
        assert_equal random_cipher.encrypt(string, false, false), cipher.encrypt(string, false, false), "Encrypted values differ"
      end

      should "encrypt and then decrypt without a header" do
        assert encrypted = @cipher.binary_encrypt(@social_security_number,false,false,false)
        assert_equal @social_security_number, @cipher.decrypt(encrypted)
      end

      should "encrypt and then decrypt using random iv" do
        assert encrypted = @cipher.encrypt(@social_security_number, random_iv=true)
        assert_equal @social_security_number, @cipher.decrypt(encrypted)
      end

      should "encrypt and then decrypt using random iv with compression" do
        assert encrypted = @cipher.encrypt(@social_security_number, random_iv=true, compress=true)
        assert_equal @social_security_number, @cipher.decrypt(encrypted)
      end

    end

  end
end