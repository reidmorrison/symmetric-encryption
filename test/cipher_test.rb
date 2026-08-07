require_relative "test_helper"

# Tests for SymmetricEncryption::Cipher
class CipherTest < Minitest::Test
  ["aes-128-cbc"].each do |cipher_name|
    describe "Cipher: #{cipher_name}" do
      describe "standalone" do
        it "allows setting the cipher_name" do
          cipher = SymmetricEncryption::Cipher.new(
            cipher_name: cipher_name,
            key:         "1234567890ABCDEF",
            iv:          "1234567890ABCDEF",
            encoding:    :none
          )

          assert_equal cipher_name, cipher.cipher_name
        end

        it "does not require an iv" do
          cipher = SymmetricEncryption::Cipher.new(
            key:               "1234567890ABCDEF",
            cipher_name:       cipher_name,
            encoding:          :none,
            always_add_header: false
          )

          assert result = cipher.encrypt("Hello World")
          assert_equal "Hello World", cipher.decrypt(result)
        end

        it "throw an exception on bad data" do
          cipher = SymmetricEncryption::Cipher.new(
            cipher_name: cipher_name,
            key:         "1234567890ABCDEF",
            iv:          "1234567890ABCDEF",
            encoding:    :none
          )
          assert_raises OpenSSL::Cipher::CipherError do
            cipher.decrypt("bad data")
          end
        end
      end

      [false, true].each do |always_add_header|
        %i[none base64 base64strict base64urlsafe base16].each do |encoding|
          describe "encoding: #{encoding} with#{'out' unless always_add_header} header" do
            before do
              @social_security_number = "987654321"
              @encrypted_values       = {
                "aes-128-cbc" => {
                  base64:        {
                    header:    "QEVuQwAAyTeLjsHTa8ykoO95K0KQmg==\n",
                    no_header: "yTeLjsHTa8ykoO95K0KQmg==\n"
                  },
                  base64strict:  {
                    header:    "QEVuQwAAyTeLjsHTa8ykoO95K0KQmg==",
                    no_header: "yTeLjsHTa8ykoO95K0KQmg=="
                  },
                  base64urlsafe: {
                    header:    "QEVuQwAAyTeLjsHTa8ykoO95K0KQmg==",
                    no_header: "yTeLjsHTa8ykoO95K0KQmg=="
                  },
                  base16:        {
                    header:    "40456e430000c9378b8ec1d36bcca4a0ef792b42909a",
                    no_header: "c9378b8ec1d36bcca4a0ef792b42909a"
                  },
                  none:          {
                    header:    "@EnC\x00\x00\xC97\x8B\x8E\xC1\xD3k\xCC\xA4\xA0\xEFy+B\x90\x9A",
                    no_header: "\xC97\x8B\x8E\xC1\xD3k\xCC\xA4\xA0\xEFy+B\x90\x9A"
                  }
                }
              }

              @non_utf8 = "\xc2".b
              @cipher   = SymmetricEncryption::Cipher.new(
                key:               "ABCDEF1234567890",
                iv:                "ABCDEF1234567890",
                cipher_name:       cipher_name,
                encoding:          encoding,
                always_add_header: always_add_header
              )

              h = @encrypted_values[cipher_name][encoding] if @encrypted_values[cipher_name]
              unless h
                skip "Add @encrypted_values for cipher_name: #{cipher_name} and encoding: #{encoding}, value: #{@cipher.encrypt(@social_security_number).inspect}"
              end
              @social_security_number_encrypted = h[always_add_header ? :header : :no_header]

              @social_security_number_encrypted = @social_security_number_encrypted.b if encoding == :none
            end

            it "encrypt simple string" do
              assert encrypted = @cipher.encrypt(@social_security_number)
              assert_equal @social_security_number_encrypted, encrypted
            end

            it "decrypt string" do
              assert decrypted = @cipher.decrypt(@social_security_number_encrypted)
              assert_equal @social_security_number, decrypted
              assert_equal Encoding.find("utf-8"), decrypted.encoding, decrypted
            end

            it "encrypt and decrypt string" do
              assert encrypted = @cipher.encrypt(@social_security_number)
              assert_equal @social_security_number_encrypted, encrypted
              assert decrypted = @cipher.decrypt(encrypted)
              assert_equal @social_security_number, decrypted
              assert_equal Encoding.find("utf-8"), decrypted.encoding, decrypted
            end

            it "return BINARY encoding for non-UTF-8 encrypted data" do
              assert_equal Encoding.find("binary"), @non_utf8.encoding
              assert_predicate @non_utf8, :valid_encoding?
              assert encrypted = @cipher.encrypt(@non_utf8)
              assert decrypted = @cipher.decrypt(encrypted)
              assert_predicate decrypted, :valid_encoding?
              assert_equal Encoding.find("binary"), decrypted.encoding, decrypted
              assert_equal @non_utf8, decrypted
            end

            it "return nil when encrypting nil" do
              assert_nil @cipher.encrypt(nil)
            end

            it "return '' when encrypting ''" do
              assert_equal "", @cipher.encrypt("")
            end

            it "return nil when decrypting nil" do
              assert_nil @cipher.decrypt(nil)
            end

            it "return '' when decrypting ''" do
              assert_equal "", @cipher.decrypt("")
            end
          end
        end
      end

      describe "with configuration" do
        before do
          @cipher = SymmetricEncryption::Cipher.new(
            key:         "1234567890ABCDEF",
            iv:          "1234567890ABCDEF",
            cipher_name: "aes-128-cbc",
            encoding:    :none
          )
          @social_security_number = "987654321"

          @social_security_number_encrypted = "A\335*\314\336\250V\340\023%\000S\177\305\372\266".b

          @sample_data = [
            {text: "555052345", encrypted: ""}
          ]
        end

        describe "with header" do
          before do
            @social_security_number = "987654321"
          end

          it "build and parse header" do
            key = SymmetricEncryption::Key.new(cipher_name: "aes-128-cbc")
            # Test Deprecated method
            binary_header = SymmetricEncryption::Cipher.build_header(
              SymmetricEncryption.cipher.version,
              true,
              key.iv,
              key.key,
              key.cipher_name
            )
            header = SymmetricEncryption::Header.new
            header.parse(binary_header)

            assert_predicate header, :compressed?
            assert random_cipher = SymmetricEncryption::Cipher.new(iv: key.iv, key: key.key, cipher_name: key.cipher_name)
            assert_equal random_cipher.cipher_name, header.cipher_name, "Ciphers differ"
            assert_equal random_cipher.send(:key), header.key, "Keys differ"
            assert_equal random_cipher.send(:iv), header.iv, "IVs differ"

            string = "Hello World"
            cipher = SymmetricEncryption::Cipher.new(key: header.key, iv: header.iv, cipher_name: header.cipher_name)
            # Test Encryption
            assert_equal random_cipher.encrypt(string), cipher.encrypt(string), "Encrypted values differ"
          end

          it "encrypt and then decrypt without a header" do
            assert encrypted = @cipher.binary_encrypt(@social_security_number, header: false)
            assert_equal @social_security_number, @cipher.decrypt(encrypted)
          end

          it "encrypt and then decrypt using random iv" do
            assert encrypted = @cipher.encrypt(@social_security_number, random_iv: true)
            assert_equal @social_security_number, @cipher.decrypt(encrypted)
          end

          it "encrypt and then decrypt using random iv with compression" do
            assert encrypted = @cipher.encrypt(@social_security_number, random_iv: true, compress: true)
            assert_equal @social_security_number, @cipher.decrypt(encrypted)
          end
        end
      end
    end
  end

  describe SymmetricEncryption::Cipher do
    let :cipher do
      SymmetricEncryption::Cipher.new(
        cipher_name: "aes-128-cbc",
        key:         "1234567890ABCDEF",
        iv:          "1234567890ABCDEF",
        version:     3
      )
    end

    describe "#initialize" do
      it "rejects a version outside of a single byte" do
        assert_raises(ArgumentError) { SymmetricEncryption::Cipher.new(key: "1234567890ABCDEF", version: 256) }
        assert_raises(ArgumentError) { SymmetricEncryption::Cipher.new(key: "1234567890ABCDEF", version: -1) }
      end
    end

    describe "#random_key" do
      it "generates a key of the correct size" do
        assert_equal 16, cipher.random_key.size
      end

      it "generates a different key every time" do
        refute_equal cipher.random_key, cipher.random_key
      end
    end

    describe "#random_iv" do
      it "generates an iv of the correct size" do
        assert_equal 16, cipher.random_iv.size
      end

      it "generates a different iv every time" do
        refute_equal cipher.random_iv, cipher.random_iv
      end
    end

    describe "#block_size" do
      it "returns the block size of the cipher" do
        assert_equal 16, cipher.block_size
      end
    end

    describe "#encoding=" do
      it "discards the encoder derived from the previous encoding" do
        cipher.encoding = :base64

        assert_instance_of SymmetricEncryption::Encoder::Base64, cipher.encoder

        cipher.encoding = :base16

        assert_instance_of SymmetricEncryption::Encoder::Base16, cipher.encoder
      end

      it "discards the magic header derived from the previous encoding" do
        cipher.encoding = :base64

        assert_equal "QEVuQw", cipher.encoded_magic_header

        cipher.encoding = :base16

        assert_equal "40456e43", cipher.encoded_magic_header
      end
    end

    describe "#inspect" do
      it "does not include the key" do
        refute_includes cipher.inspect, "1234567890ABCDEF1234567890ABCDEF"
        assert_includes cipher.inspect, "[FILTERED]"
      end

      it "includes the version" do
        assert_includes cipher.inspect, "@version=3"
      end
    end

    describe "deprecated header helpers" do
      # The header holds the cipher version, which is looked up in the global ciphers when parsed.
      let :encrypted do
        SymmetricEncryption.cipher.binary_encrypt("Hello World", header: true)
      end

      it ".has_header?" do
        assert SymmetricEncryption::Cipher.has_header?(encrypted)
        refute SymmetricEncryption::Cipher.has_header?("Not encrypted")
      end

      it ".parse_header!" do
        header = SymmetricEncryption::Cipher.parse_header!(encrypted.dup)

        assert_equal SymmetricEncryption.cipher.version, header.version
      end

      it ".parse_header! returns nil when there is no header" do
        assert_nil SymmetricEncryption::Cipher.parse_header!(+"Not encrypted")
      end

      it ".build_header" do
        header = SymmetricEncryption::Cipher.build_header(3, false, "1234567890ABCDEF")

        assert SymmetricEncryption::Header.present?(header)
      end
    end
  end
end
