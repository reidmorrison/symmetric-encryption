require_relative "test_helper"

class KeyTest < Minitest::Test
  describe SymmetricEncryption::Key do
    let :random_key do
      SymmetricEncryption::Key.new
    end

    let :stored_key do
      "1234567890ABCDEF1234567890ABCDEF"
    end

    let :stored_iv do
      "ABCDEF1234567890"
    end

    let :key do
      SymmetricEncryption::Key.new(key: stored_key, iv: stored_iv)
    end

    let :ssn do
      "987654321"
    end

    let :encrypted_ssn do
      "cR\x9C,\x91\xA4{\b`\x9Fls\xA4\f\xD1\xBF".b
    end

    describe "encrypt" do
      it "empty string" do
        assert_equal "", key.encrypt("")
      end

      it "nil" do
        assert_nil key.encrypt(nil)
      end

      it "string" do
        assert_equal encrypted_ssn, key.encrypt(ssn)
      end
    end

    describe "decrypt" do
      it "empty string" do
        assert_equal "", key.decrypt("")
      end

      it "nil" do
        assert_nil key.decrypt(nil)
      end

      it "string" do
        assert_equal ssn, key.decrypt(encrypted_ssn)
      end

      it "accepts a frozen string" do
        assert_equal ssn, key.decrypt(encrypted_ssn.freeze)
      end

      it "does not change the encoding of the supplied string" do
        encrypted = encrypted_ssn.dup.force_encoding(Encoding::UTF_8)

        assert_equal ssn, key.decrypt(encrypted)
        assert_equal Encoding::UTF_8, encrypted.encoding
      end
    end

    describe "#initialize" do
      # OpenSSL only checks the length when the key is used, so without this check the config
      # that supplied the key is long gone by the time `key must be 32 bytes` is raised.
      it "rejects a key that is not the length the cipher requires" do
        error = assert_raises(ArgumentError) do
          SymmetricEncryption::Key.new(key: "1234567890ABCDEF", iv: stored_iv)
        end

        assert_includes error.message, "The key supplied for cipher_name: \"aes-256-cbc\""
        assert_includes error.message, "must be exactly 32 bytes, but is 16 bytes"
      end

      # A hex encoded key holds the right number of bits in twice as many bytes. Issue #122.
      it "rejects a hex encoded key" do
        error = assert_raises(ArgumentError) do
          SymmetricEncryption::Key.new(key: "b1c7d3086cb05b5056a6b30f5e55180cec6fb28ef1650ded94947787da9588c2")
        end

        assert_includes error.message, "must be exactly 32 bytes, but is 64 bytes"
        assert_includes error.message, "!!binary"
      end

      it "rejects an iv that is not the length the cipher requires" do
        error = assert_raises(ArgumentError) do
          SymmetricEncryption::Key.new(key: stored_key, iv: "ABCDEF12")
        end

        assert_includes error.message, "The iv supplied for cipher_name: \"aes-256-cbc\""
        assert_includes error.message, "must be exactly 16 bytes, but is 8 bytes"
      end

      # A key written into the config file with \x escapes is parsed by YAML as codepoints, not
      # bytes, so it ends up the right number of characters long and too many bytes long. Issue #71.
      it "counts bytes, not characters" do
        multi_byte_key = "é" * 32

        assert_equal 32, multi_byte_key.size

        error = assert_raises(ArgumentError) { SymmetricEncryption::Key.new(key: multi_byte_key) }

        assert_includes error.message, "must be exactly 32 bytes, but is 64 bytes"
      end
    end

    describe "key" do
      it "creates random key by default" do
        assert key = random_key.key
        refute_equal key, SymmetricEncryption::Key.new.key
      end

      it "stores" do
        assert_equal stored_key, key.key
      end

      it "holds the key and iv as binary, whatever encoding they arrived in" do
        assert_equal Encoding::BINARY, key.key.encoding
        assert_equal Encoding::BINARY, key.iv.encoding
      end
    end

    describe "iv" do
      it "creates random iv by default" do
        assert iv = random_key.iv
        refute_equal iv, SymmetricEncryption::Key.new.iv
      end

      it "stores" do
        assert_equal stored_iv, key.iv
      end
    end

    describe "authenticated cipher" do
      let :authenticated_key do
        SymmetricEncryption::Key.new(key: stored_key, cipher_name: "aes-256-gcm")
      end

      it "round trips" do
        assert_equal ssn, authenticated_key.decrypt(authenticated_key.encrypt(ssn))
      end

      it "appends the auth tag to the encrypted data" do
        # The key encrypting keys have no header to carry the tag in, so it goes on the end.
        encrypted = authenticated_key.encrypt(ssn)

        assert_equal ssn.length + SymmetricEncryption::Header::AUTH_TAG_SIZE, encrypted.length
      end

      it "rejects data that has been tampered with" do
        encrypted = authenticated_key.encrypt(ssn)
        encrypted.setbyte(0, encrypted.getbyte(0) ^ 0x01)

        assert_raises OpenSSL::Cipher::CipherError do
          authenticated_key.decrypt(encrypted)
        end
      end

      it "rejects data too short to hold an auth tag" do
        error = assert_raises SymmetricEncryption::CipherError do
          authenticated_key.decrypt("too short")
        end

        assert_includes error.message, "too short to hold its 16 byte auth tag"
      end

      it "secures a data encryption key, as a key encrypting key" do
        dek = SymmetricEncryption::Key.new(cipher_name: "aes-256-gcm")

        assert_equal dek.key, authenticated_key.decrypt(authenticated_key.encrypt(dek.key))
      end
    end
  end
end
