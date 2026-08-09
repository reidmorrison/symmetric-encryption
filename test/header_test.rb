require_relative "test_helper"

class CipherTest < Minitest::Test
  describe SymmetricEncryption::Header do
    let :clear_value do
      "Hello World"
    end

    let :random_iv do
      false
    end

    let :compress do
      false
    end

    let :binary_encrypted_value do
      SymmetricEncryption.cipher.binary_encrypt(clear_value, random_iv: random_iv, compress: compress)
    end

    let :header do
      header = SymmetricEncryption::Header.new
      header.parse(binary_encrypted_value)
      header
    end

    describe "#new" do
      it "sets defaults" do
        header = SymmetricEncryption::Header.new

        assert_equal SymmetricEncryption.cipher.version, header.version
        refute_predicate header, :compressed?
        refute header.iv
        refute header.key
        refute header.cipher_name
        refute header.auth_tag
      end
    end

    describe ".present?" do
      it "has a header" do
        assert SymmetricEncryption::Header.present?(binary_encrypted_value)
      end

      it "does not have a header" do
        refute SymmetricEncryption::Header.present?(clear_value)
      end

      it "does not have a header when nil" do
        refute SymmetricEncryption::Header.present?(nil)
      end

      it "does not have a header when empty string" do
        refute SymmetricEncryption::Header.present?("")
      end

      it "accepts a frozen buffer" do
        assert SymmetricEncryption::Header.present?(binary_encrypted_value.freeze)
      end

      it "does not change the encoding of the supplied buffer" do
        buffer = binary_encrypted_value.dup.force_encoding(Encoding::UTF_8)

        assert SymmetricEncryption::Header.present?(buffer)
        assert_equal Encoding::UTF_8, buffer.encoding
      end
    end

    describe "#cipher" do
      it "returns the global cipher used to encrypt the value" do
        assert_equal SymmetricEncryption.cipher, header.cipher
      end
    end

    describe "#version" do
      it "returns the global cipher used to encrypt the value" do
        assert_equal SymmetricEncryption.cipher.version, header.version
      end
    end

    describe "#cipher_name" do
      it "returns nil when cipher name was not overridden" do
        assert_nil header.cipher_name
      end
    end

    describe "#key" do
      it "returns nil when key was not overridden" do
        assert_nil header.key
      end
    end

    describe "#compress" do
      it "encrypted string" do
        refute_predicate header, :compressed?
      end

      describe "with compression" do
        let :compress do
          true
        end

        it "encrypted string" do
          assert_predicate header, :compressed?
        end
      end
    end

    describe "#to_s" do
      it "round trips through #parse" do
        original = SymmetricEncryption::Header.new(
          version:     2,
          compress:    true,
          iv:          "1234567890ABCDEF",
          cipher_name: "aes-256-cbc"
        )

        parsed = SymmetricEncryption::Header.new
        parsed.parse(original.to_s)

        assert_equal 2, parsed.version
        assert_predicate parsed, :compressed?
        assert_equal "1234567890ABCDEF", parsed.iv
        assert_equal "aes-256-cbc", parsed.cipher_name
      end

      it "omits the fields that were not set" do
        parsed = SymmetricEncryption::Header.new
        parsed.parse(SymmetricEncryption::Header.new(version: 2).to_s)

        assert_nil parsed.iv
        assert_nil parsed.key
        assert_nil parsed.cipher_name
        assert_nil parsed.auth_tag
        refute_predicate parsed, :compressed?
      end

      it "round trips an auth tag" do
        auth_tag = "1234567890ABCDEF"
        original = SymmetricEncryption::Header.new(version: 2, iv: "1234567890AB", auth_tag: auth_tag)

        parsed = SymmetricEncryption::Header.new
        parsed.parse(original.to_s)

        assert_predicate parsed, :authenticated?
        assert_equal auth_tag, parsed.auth_tag
      end

      it "raises when the auth tag is not known yet" do
        header = SymmetricEncryption::Header.new(version: 2, authenticated: true)

        error = assert_raises SymmetricEncryption::CipherError do
          header.to_s
        end

        assert_includes error.message, "auth tag has to be set"
      end
    end

    describe "#auth_data" do
      # The auth data is everything before the auth tag, so that it can be handed to an
      # authenticated cipher before the tag exists.
      it "is the header without the auth tag" do
        header = SymmetricEncryption::Header.new(version: 2, iv: "1234567890AB", authenticated: true)
        auth_data = header.auth_data
        header.auth_tag = "1234567890ABCDEF"

        assert_equal "#{auth_data}#{[16].pack('v')}1234567890ABCDEF", header.to_s
      end

      it "matches the bytes parsed back out of the encrypted value" do
        header = SymmetricEncryption::Header.new(version: 2, iv: "1234567890AB", authenticated: true)
        header.auth_tag = "1234567890ABCDEF"

        parsed = SymmetricEncryption::Header.new
        parsed.parse(header.to_s)

        assert_equal header.auth_data, parsed.auth_data
      end
    end

    describe "#auth_tag=" do
      # OpenSSL accepts a truncated auth tag, and a truncated tag is not expensive to forge.
      it "rejects an auth tag that is too short" do
        error = assert_raises SymmetricEncryption::CipherError do
          SymmetricEncryption::Header.new(version: 2).auth_tag = "1234"
        end

        assert_includes error.message, "must be exactly 16 bytes"
      end

      it "rejects an auth tag that is too long" do
        assert_raises SymmetricEncryption::CipherError do
          SymmetricEncryption::Header.new(version: 2).auth_tag = "1234567890ABCDEFG"
        end
      end
    end

    describe "#parse" do
      it "nil string" do
        header = SymmetricEncryption::Header.new

        assert_equal 0, header.parse(nil)
      end

      it "empty string" do
        header = SymmetricEncryption::Header.new

        assert_equal 0, header.parse("")
      end

      it "unencrypted string" do
        header = SymmetricEncryption::Header.new

        assert_equal 0, header.parse("hello there")
      end

      it "encrypted string" do
        header = SymmetricEncryption::Header.new

        assert_equal 6, header.parse(binary_encrypted_value)
      end

      it "accepts a frozen buffer" do
        header = SymmetricEncryption::Header.new

        assert_equal 6, header.parse(binary_encrypted_value.freeze)
      end

      it "does not change the encoding of the supplied buffer" do
        header = SymmetricEncryption::Header.new
        buffer = binary_encrypted_value.dup.force_encoding(Encoding::UTF_8)

        assert_equal 6, header.parse(buffer)
        assert_equal Encoding::UTF_8, buffer.encoding
      end

      describe "with random_iv" do
        let :random_iv do
          true
        end

        it "encrypted string" do
          header = SymmetricEncryption::Header.new

          assert_equal 24, header.parse(binary_encrypted_value)
        end

        describe "with compression" do
          let :compress do
            true
          end

          it "encrypted string" do
            assert_predicate header, :compressed?
          end
        end
      end
    end

    describe "#parse!" do
      it "nil string" do
        header = SymmetricEncryption::Header.new

        assert_nil header.parse!(nil)
      end

      it "empty string" do
        header = SymmetricEncryption::Header.new

        assert_nil header.parse!(+"")
      end

      it "unencrypted string" do
        header = SymmetricEncryption::Header.new

        assert_nil header.parse!(+"hello there")
      end

      it "encrypted string" do
        header    = SymmetricEncryption::Header.new
        remainder = header.parse!(binary_encrypted_value.dup)

        assert_equal SymmetricEncryption.cipher.version, header.version
        refute_predicate header, :compressed?
        refute header.iv
        refute header.key
        refute header.cipher_name
        refute header.auth_tag

        # Decrypt with this new header
        encrypted_without_header = SymmetricEncryption.cipher.binary_encrypt(clear_value, header: false)

        assert_equal encrypted_without_header, remainder

        assert_equal clear_value, SymmetricEncryption.cipher.binary_decrypt(remainder, header: header)
      end

      describe "with random_iv" do
        let :random_iv do
          true
        end

        it "encrypted string" do
          header = SymmetricEncryption::Header.new

          assert remainder = header.parse!(binary_encrypted_value)
          assert_equal SymmetricEncryption.cipher.version, header.version
          refute_predicate header, :compressed?
          assert header.iv
          refute header.key
          refute header.cipher_name
          refute header.auth_tag
          assert_equal clear_value, SymmetricEncryption.cipher.binary_decrypt(remainder, header: header)
        end
      end
    end

    describe "#iv" do
      it "encrypted string" do
        header = SymmetricEncryption::Header.new
        header.parse(binary_encrypted_value)

        assert_nil header.iv
      end

      describe "with random_iv" do
        let :random_iv do
          true
        end

        it "encrypted string" do
          assert header.iv
          refute_equal SymmetricEncryption.cipher.iv, header.iv
        end
      end
    end
  end
end
