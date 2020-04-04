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
        refute header.compressed?
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
        refute header.compressed?
      end

      describe "with compression" do
        let :compress do
          true
        end

        it "encrypted string" do
          assert header.compressed?
        end
      end
    end

    describe "#to_s" do
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
            assert header.compressed?
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
        assert_nil header.parse!("")
      end

      it "unencrypted string" do
        header = SymmetricEncryption::Header.new
        assert_nil header.parse!("hello there")
      end

      it "encrypted string" do
        header    = SymmetricEncryption::Header.new
        remainder = header.parse!(binary_encrypted_value.dup)
        assert_equal SymmetricEncryption.cipher.version, header.version
        refute header.compressed?
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
          refute header.compressed?
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
