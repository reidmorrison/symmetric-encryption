require "#{File.dirname(__FILE__)}/test_helper"

# Unit Test for SymmetricEncryption
#
class SymmetricEncryptionTest < Test::Unit::TestCase
  context 'SymmetricEncryption' do

    config_file = File.join(File.dirname(__FILE__), 'config', 'symmetric-encryption.yml')
    config_yaml = YAML.load_file(config_file)

    [
     ["test", {}],
     ["heroku", {"TEST_SYM_ENC_KEY_VAR" => config_yaml["test"]["private_rsa_key"]}]
    ].each do |env, envvars|
      context "configuration for env #{env}" do
        orig_envvars = {}

        setup do
          envvars.each do |key, val|
            orig_envvars[key] = ENV[key]
            ENV[key] = val
          end
          @config = SymmetricEncryption.send(:read_config, config_file, env)
          assert @cipher_v1 = @config[:ciphers][0]
          assert @cipher_v0 = @config[:ciphers][1]
        end

        teardown do
          envvars.keys.each do |key|
            ENV[key] = orig_envvars[key]
          end
        end

        should "match config file for first cipher" do
          cipher = SymmetricEncryption.cipher
          assert_equal @cipher_v1[:cipher_name], cipher.cipher_name
          assert_equal @cipher_v1[:version], cipher.version
          assert_equal false, SymmetricEncryption.secondary_ciphers.include?(cipher)
        end

        should "match config file for v1 cipher" do
          cipher = SymmetricEncryption.cipher(1)
          assert @cipher_v1[:cipher_name]
          assert @cipher_v1[:version]
          assert_equal @cipher_v1[:cipher_name], cipher.cipher_name
          assert_equal @cipher_v1[:version], cipher.version
          assert_equal false, SymmetricEncryption.secondary_ciphers.include?(cipher)
        end

        should "match config file for v0 cipher" do
          cipher = SymmetricEncryption.cipher(0)
          assert @cipher_v0[:cipher_name]
          assert @cipher_v0[:version]
          assert_equal @cipher_v0[:cipher_name], cipher.cipher_name
          assert_equal @cipher_v0[:version], cipher.version
          assert_equal true, SymmetricEncryption.secondary_ciphers.include?(cipher)
        end

        should 'read ciphers from config file' do
        end
      end

      SymmetricEncryption::Cipher::ENCODINGS.each do |encoding|
        context "encoding: #{encoding}" do
          setup do
            @social_security_number = "987654321"
            @social_security_number_encrypted =
              case encoding
              when :base64
                "S+8X1NRrqdfEIQyFHVPuVA==\n"
              when :base64strict
                "S+8X1NRrqdfEIQyFHVPuVA=="
              when :base16
                "4bef17d4d46ba9d7c4210c851d53ee54"
              when :none
                "K\xEF\x17\xD4\xD4k\xA9\xD7\xC4!\f\x85\x1DS\xEET".force_encoding(Encoding.find("binary"))
              else
                raise "Add test for encoding: #{encoding}"
              end
            @social_security_number_encrypted_with_secondary_1 = "D1UCu38pqJ3jc0GvwJHiow==\n"
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
            assert_equal @social_security_number, SymmetricEncryption.decrypt(@social_security_number_encrypted)
          end

          should "determine if string is encrypted" do
            assert_equal true, SymmetricEncryption.encrypted?(@social_security_number_encrypted)
            assert_equal false, SymmetricEncryption.encrypted?(@social_security_number)
          end

          should "decrypt with secondary key when first one fails" do
            assert_equal @social_security_number, SymmetricEncryption.decrypt(@social_security_number_encrypted_with_secondary_1)
          end
        end
      end

      context "random iv" do
        setup do
          @social_security_number = "987654321"
        end

        should "encrypt and then decrypt using random iv" do
          # Encrypt with random iv
          assert encrypted = SymmetricEncryption.encrypt(@social_security_number, true)
          assert_equal true, SymmetricEncryption.encrypted?(encrypted)
          assert_equal @social_security_number, SymmetricEncryption.decrypt(encrypted)
        end

        should "encrypt and then decrypt using random iv with compression" do
          # Encrypt with random iv and compress
          assert encrypted = SymmetricEncryption.encrypt(@social_security_number, true, true)
          assert_equal true, SymmetricEncryption.encrypted?(encrypted)
          assert_equal @social_security_number, SymmetricEncryption.decrypt(encrypted)
        end
      end
    end
  end
end
