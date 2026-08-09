require_relative "test_helper"

# Encrypting different data with different keys, by giving each key its own version in
# `symmetric-encryption.yml` and naming the version when encrypting.
class MultipleCiphersTest < Minitest::Test
  describe SymmetricEncryption do
    let :clear_value do
      "Hello World"
    end

    # A version that is in test/config/symmetric-encryption.yml, but is not the primary cipher.
    let :the_other_version do
      6
    end

    describe ".encrypt" do
      it "encrypts with the version supplied" do
        encrypted = SymmetricEncryption.encrypt(clear_value, version: the_other_version)

        assert_equal the_other_version, SymmetricEncryption.header(encrypted).version
      end

      it "encrypts with the primary cipher when no version is supplied" do
        encrypted = SymmetricEncryption.encrypt(clear_value)

        assert_equal SymmetricEncryption.cipher.version, SymmetricEncryption.header(encrypted).version
      end

      # The version is in the header, so nothing has to be supplied when reading it back.
      it "decrypts without being told the version" do
        encrypted = SymmetricEncryption.encrypt(clear_value, version: the_other_version)

        assert_equal clear_value, SymmetricEncryption.decrypt(encrypted)
      end

      it "coerces the type with the version supplied" do
        encrypted = SymmetricEncryption.encrypt(21, type: :integer, version: the_other_version)

        assert_equal 21, SymmetricEncryption.decrypt(encrypted, type: :integer)
      end

      it "uses the always_add_header of the cipher it encrypts with" do
        cipher = SymmetricEncryption.cipher(the_other_version)

        assert_equal cipher.always_add_header, SymmetricEncryption::Header.present?(
          cipher.decode(SymmetricEncryption.encrypt(clear_value, version: the_other_version))
        )
      end

      it "raises when no cipher has that version" do
        error = assert_raises SymmetricEncryption::CipherError do
          SymmetricEncryption.encrypt(clear_value, version: 99)
        end

        assert_includes error.message, "version:99"
      end
    end

    # Returning nil left the caller with a NoMethodError that named neither the version nor the
    # versions that are available.
    describe ".cipher" do
      it "raises when no cipher has that version" do
        error = assert_raises SymmetricEncryption::CipherError do
          SymmetricEncryption.cipher(99)
        end

        assert_includes error.message, "version:99"
        assert_includes error.message, "Available versions:"
      end

      it "returns the cipher with that version" do
        assert_equal the_other_version, SymmetricEncryption.cipher(the_other_version).version
      end

      it "returns the configured cipher with version zero" do
        assert_equal 0, SymmetricEncryption.cipher(0).version
      end

      # A value with no header reports version 0, and was encrypted by whichever cipher was
      # primary when it was written, so version 0 falls back to the primary cipher.
      it "returns the primary cipher for version zero when no cipher has that version" do
        original_secondary_ciphers = SymmetricEncryption.secondary_ciphers
        begin
          SymmetricEncryption.secondary_ciphers = []

          assert_equal SymmetricEncryption.cipher, SymmetricEncryption.cipher(0)
        ensure
          SymmetricEncryption.secondary_ciphers = original_secondary_ciphers
        end
      end
    end

    describe ".decrypt" do
      # The version supplied is only used when the value has no header to take it from.
      it "raises when no cipher has the version supplied" do
        headerless = SymmetricEncryption.cipher.encrypt(clear_value, header: false)

        assert_raises SymmetricEncryption::CipherError do
          SymmetricEncryption.decrypt(headerless, version: 99)
        end
      end

      it "ignores the version supplied when the value has a header" do
        encrypted = SymmetricEncryption.encrypt(clear_value)

        assert_equal clear_value, SymmetricEncryption.decrypt(encrypted, version: the_other_version)
      end
    end
  end
end
