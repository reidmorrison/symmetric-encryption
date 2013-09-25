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
  context 'SymmetricEncryption' do

    context 'configuration' do
      setup do
        @ciphers = SymmetricEncryption.send(:read_config, File.join(File.dirname(__FILE__), 'config', 'symmetric-encryption.yml'), 'test')
        @cipher_v2, @cipher_v1, @cipher_v0 = @ciphers
      end

      should "match config file for first cipher" do
        cipher = SymmetricEncryption.cipher
        assert @cipher_v2.send(:key)
        assert @cipher_v2.send(:iv)
        assert @cipher_v2.version
        assert_equal @cipher_v2.cipher_name, cipher.cipher_name
        assert_equal @cipher_v2.version, cipher.version
        assert_equal false, SymmetricEncryption.secondary_ciphers.include?(cipher)
      end

      should "match config file for v1 cipher" do
        cipher = SymmetricEncryption.cipher(2)
        assert @cipher_v2.cipher_name
        assert @cipher_v2.version
        assert_equal @cipher_v2.cipher_name, cipher.cipher_name
        assert_equal @cipher_v2.version, cipher.version
        assert_equal false, SymmetricEncryption.secondary_ciphers.include?(cipher)
      end

      should "match config file for v0 cipher" do
        cipher = SymmetricEncryption.cipher(0)
        assert @cipher_v0.cipher_name
        assert @cipher_v0.version
        assert_equal @cipher_v0.cipher_name, cipher.cipher_name
        assert_equal @cipher_v0.version, cipher.version
        assert_equal true, SymmetricEncryption.secondary_ciphers.include?(cipher)
      end
    end

    SymmetricEncryption::Cipher::ENCODINGS.each do |encoding|
      context "encoding: #{encoding}" do
        setup do
          @social_security_number = "987654321"
          @social_security_number_encrypted =
            case encoding
          when :base64
            "QEVuQwIAS+8X1NRrqdfEIQyFHVPuVA==\n"
          when :base64strict
            "QEVuQwIAS+8X1NRrqdfEIQyFHVPuVA=="
          when :base16
            "40456e4302004bef17d4d46ba9d7c4210c851d53ee54"
          when :none
            "@EnC\x02\x00K\xEF\x17\xD4\xD4k\xA9\xD7\xC4!\f\x85\x1DS\xEET".force_encoding(Encoding.find("binary"))
          else
            raise "Add test for encoding: #{encoding}"
          end
          @social_security_number_encrypted_with_secondary_1 = "D1UCu38pqJ3jc0GvwJHiow==\n"
          @non_utf8 = "\xc2".force_encoding('binary')
          @encoding = SymmetricEncryption.cipher.encoding
          SymmetricEncryption.cipher.encoding = encoding
        end

        teardown do
          SymmetricEncryption.cipher.encoding = @encoding
        end

        should "encrypt simple string" do
          assert_equal @social_security_number_encrypted, SymmetricEncryption.encrypt(@social_security_number)
        end

        should "decrypt string" do
          assert decrypted = SymmetricEncryption.decrypt(@social_security_number_encrypted)
          assert_equal @social_security_number, decrypted
          assert_equal Encoding.find('utf-8'), decrypted.encoding, decrypted
        end

        should 'return BINARY encoding for non-UTF-8 encrypted data' do
          assert_equal Encoding.find('binary'), @non_utf8.encoding
          assert_equal true, @non_utf8.valid_encoding?
          assert encrypted = SymmetricEncryption.encrypt(@non_utf8)
          assert decrypted = SymmetricEncryption.decrypt(encrypted)
          assert_equal true, decrypted.valid_encoding?
          assert_equal Encoding.find('binary'), decrypted.encoding, decrypted
          assert_equal @non_utf8, decrypted
        end

        should "return nil when encrypting nil" do
          assert_equal nil, SymmetricEncryption.encrypt(nil)
        end

        should "return '' when encrypting ''" do
          assert_equal '', SymmetricEncryption.encrypt('')
        end

        should "return nil when decrypting nil" do
          assert_equal nil, SymmetricEncryption.decrypt(nil)
        end

        should "return '' when decrypting ''" do
          assert_equal '', SymmetricEncryption.decrypt('')
        end

        should "determine if string is encrypted" do
          assert_equal true, SymmetricEncryption.encrypted?(@social_security_number_encrypted)
          assert_equal false, SymmetricEncryption.encrypted?(@social_security_number)
        end
      end

      context "using select_cipher" do
        setup do
          @social_security_number = "987654321"
          # Encrypt data without a header and encode with base64 which has a trailing '\n'
          @encrypted_0_ssn = SymmetricEncryption.cipher(0).encode(SymmetricEncryption.cipher(0).binary_encrypt(@social_security_number,false,false,false))

          SymmetricEncryption.select_cipher do |encoded_str, decoded_str|
            # Use cipher version 0 if the encoded string ends with "\n" otherwise
            # use the current default cipher
            encoded_str.end_with?("\n") ? SymmetricEncryption.cipher(0) : SymmetricEncryption.cipher
          end
        end

        teardown do
          # Clear out select_cipher
          SymmetricEncryption.select_cipher
        end

        should "decrypt string without a header using an old cipher" do
          assert_equal @social_security_number, SymmetricEncryption.decrypt(@encrypted_0_ssn)
        end
      end

      context "without select_cipher" do
        setup do
          @social_security_number = "987654321"
          # Encrypt data without a header and encode with base64 which has a trailing '\n'
          assert @encrypted_0_ssn = SymmetricEncryption.cipher(0).encode(SymmetricEncryption.cipher(0).binary_encrypt(@social_security_number,false,false,false))
        end

        should "decrypt string without a header using an old cipher" do
          assert_raises OpenSSL::Cipher::CipherError do
            SymmetricEncryption.decrypt(@encrypted_0_ssn)
          end
        end
      end
    end

    context "random iv" do
      setup do
        @social_security_number = "987654321"
      end

      should "encrypt and then decrypt using random iv" do
        # Encrypt with random iv
        assert encrypted = SymmetricEncryption.encrypt(@social_security_number, random_iv=true)
        assert_equal true, SymmetricEncryption.encrypted?(encrypted)
        assert_equal @social_security_number, SymmetricEncryption.decrypt(encrypted)
      end

      should "encrypt and then decrypt using random iv with compression" do
        # Encrypt with random iv and compress
        assert encrypted = SymmetricEncryption.encrypt(@social_security_number, random_iv=true, compress=true)
        assert_equal true, SymmetricEncryption.encrypted?(encrypted)
        assert_equal @social_security_number, SymmetricEncryption.decrypt(encrypted)
      end
    end

  end

end
