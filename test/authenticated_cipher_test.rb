require_relative "test_helper"

# Authenticated ciphers, such as aes-256-gcm, detect any change to the encrypted value instead of
# decrypting whatever they are given. Kept separate from cipher_test.rb, which covers the
# unauthenticated ciphers that every value encrypted before v5 was encrypted with.
class AuthenticatedCipherTest < Minitest::Test
  describe SymmetricEncryption::Cipher do
    let :clear_value do
      "Hello World"
    end

    let :the_cipher do
      SymmetricEncryption::Cipher.new(
        key:         "12345678901234567890123456789012",
        cipher_name: "aes-256-gcm",
        version:     2
      )
    end

    # The cipher every value encrypted before authenticated ciphers were supported was encrypted
    # with, kept alongside the new one so that those values can still be read.
    let :the_previous_cipher do
      SymmetricEncryption::Cipher.new(
        key:         "1234567890ABCDEF1234567890ABCDEF",
        iv:          "1234567890ABCDEF",
        cipher_name: "aes-256-cbc",
        version:     1
      )
    end

    let :binary_value do
      the_cipher.binary_encrypt(clear_value, random_iv: true)
    end

    # `SymmetricEncryption.cipher` is global, and the header of an encrypted value is parsed
    # against it, so it has to be set for the duration of each test and put back afterwards.
    before do
      @original_cipher            = SymmetricEncryption.cipher
      @original_secondary_ciphers = SymmetricEncryption.secondary_ciphers
      SymmetricEncryption.cipher            = the_cipher
      SymmetricEncryption.secondary_ciphers = [the_previous_cipher]
    end

    after do
      SymmetricEncryption.cipher            = @original_cipher
      SymmetricEncryption.secondary_ciphers = @original_secondary_ciphers
    end

    describe "#authenticated?" do
      it "is an authenticated cipher" do
        assert_predicate the_cipher, :authenticated?
      end

      it "is not an authenticated cipher" do
        refute_predicate the_previous_cipher, :authenticated?
      end
    end

    describe "#encrypt" do
      it "round trips" do
        assert_equal clear_value, the_cipher.decrypt(the_cipher.encrypt(clear_value))
      end

      it "round trips compressed data" do
        large = clear_value * 100
        encrypted = the_cipher.encrypt(large, compress: true, random_iv: true)

        assert_equal large, the_cipher.decrypt(encrypted)
      end

      it "returns a different value every time with a random iv" do
        refute_equal the_cipher.encrypt(clear_value, random_iv: true),
                     the_cipher.encrypt(clear_value, random_iv: true)
      end

      it "adds a header even when the cipher does not always add one" do
        cipher = SymmetricEncryption::Cipher.new(
          key: "12345678901234567890123456789012", cipher_name: "aes-256-gcm", version: 2, always_add_header: false
        )

        assert SymmetricEncryption::Header.present?(cipher.binary_encrypt(clear_value))
      end

      it "carries an auth tag in the header" do
        header = SymmetricEncryption::Header.new
        header.parse(binary_value)

        assert_predicate header, :authenticated?
        assert_equal SymmetricEncryption::Header::AUTH_TAG_SIZE, header.auth_tag.length
      end
    end

    describe "#encrypt without a random iv" do
      # Re-using one iv across different values would expose the data and make the auth tag
      # forgeable, so the iv is derived from the value instead of being re-used.
      it "returns the same value for the same input" do
        assert_equal the_cipher.encrypt(clear_value, random_iv: false),
                     the_cipher.encrypt(clear_value, random_iv: false)
      end

      it "returns a different value for a different input" do
        refute_equal the_cipher.encrypt(clear_value, random_iv: false),
                     the_cipher.encrypt("Different value", random_iv: false)
      end

      it "uses a different iv for a different input" do
        headers = [clear_value, "Different value"].collect do |value|
          header = SymmetricEncryption::Header.new
          header.parse(the_cipher.binary_encrypt(value, random_iv: false))
          header.iv
        end

        refute_equal headers.first, headers.last
      end

      it "round trips" do
        assert_equal clear_value, the_cipher.decrypt(the_cipher.encrypt(clear_value, random_iv: false))
      end

      it "does not use the configured iv" do
        cipher = SymmetricEncryption::Cipher.new(
          key: "12345678901234567890123456789012", iv: "123456789012", cipher_name: "aes-256-gcm", version: 2
        )
        header = SymmetricEncryption::Header.new
        header.parse(cipher.binary_encrypt(clear_value, random_iv: false))

        refute_equal cipher.iv, header.iv
      end
    end

    describe "#decrypt" do
      it "detects a change to the encrypted data" do
        tampered = binary_value.dup
        tampered.setbyte(tampered.bytesize - 1, tampered.getbyte(tampered.bytesize - 1) ^ 0xFF)

        assert_raises OpenSSL::Cipher::CipherError do
          the_cipher.binary_decrypt(tampered)
        end
      end

      # The header is passed to the cipher as its additional authenticated data, so the version,
      # the flags, the iv and the cipher name are covered by the auth tag as well.
      it "detects a change to the header" do
        tampered = binary_value.dup
        # Turn on the compressed flag.
        tampered.setbyte(5, tampered.getbyte(5) | 0b1000_0000)

        assert_raises OpenSSL::Cipher::CipherError do
          the_cipher.binary_decrypt(tampered)
        end
      end

      it "detects a change to the iv" do
        tampered = binary_value.dup
        tampered.setbyte(8, tampered.getbyte(8) ^ 0xFF)

        assert_raises OpenSSL::Cipher::CipherError do
          the_cipher.binary_decrypt(tampered)
        end
      end

      it "refuses a value with no auth tag" do
        unauthenticated = the_previous_cipher.binary_encrypt(clear_value, header: false)

        error = assert_raises SymmetricEncryption::CipherError do
          the_cipher.binary_decrypt(unauthenticated)
        end

        assert_includes error.message, "authenticated cipher"
      end

      # Without this an attacker could name an unauthenticated cipher in the header and have the
      # value decrypted without the auth tag being checked.
      it "refuses a value whose header names an unauthenticated cipher" do
        header = SymmetricEncryption::Header.new
        offset = header.parse(binary_value)
        forged = SymmetricEncryption::Header.new(
          version: the_cipher.version, iv: header.iv, cipher_name: "aes-256-cbc", auth_tag: header.auth_tag
        )

        error = assert_raises SymmetricEncryption::CipherError do
          the_cipher.binary_decrypt(forged.to_s + binary_value[offset..])
        end

        assert_includes error.message, "not an authenticated cipher"
      end
    end

    # A stream is authenticated a chunk at a time once there is more than one chunk of data, so
    # that it can be verified as it is read. See chunked_stream_test.rb.
    describe "files and streams" do
      let :the_file_name do
        "._authenticated_test"
      end

      after do
        FileUtils.rm_f(the_file_name)
      end

      it "round trips a file" do
        SymmetricEncryption::Writer.open(the_file_name) { |file| file.write(clear_value) }

        assert_equal clear_value, SymmetricEncryption::Reader.open(the_file_name, &:read)
      end

      it "refuses a stream that has no auth tag" do
        SymmetricEncryption::Writer.open(the_file_name, cipher_name: "aes-256-cbc") do |file|
          file.write(clear_value)
        end
        # Rewrite the header so that it names the authenticated cipher for the data itself.
        header = SymmetricEncryption::Header.new
        buffer = File.binread(the_file_name)
        offset = header.parse(buffer)
        forged = SymmetricEncryption::Header.new(
          version: header.version, iv: header.iv, key: header.key, cipher_name: "aes-256-gcm"
        )
        File.binwrite(the_file_name, forged.to_s + buffer[offset..])

        error = assert_raises SymmetricEncryption::CipherError do
          SymmetricEncryption::Reader.open(the_file_name, &:read)
        end

        assert_includes error.message, "no auth tag"
      end

      # The random key generated for the file is encrypted with the global cipher, so an
      # authenticated global cipher still protects the file's key.
      it "encrypts the file key with the authenticated cipher" do
        SymmetricEncryption::Writer.open(the_file_name, cipher_name: "aes-256-cbc") do |file|
          file.write(clear_value)
        end

        header = SymmetricEncryption::Header.new
        header.parse(File.binread(the_file_name))

        assert_equal the_cipher.version, header.version
        assert_equal clear_value, SymmetricEncryption::Reader.open(the_file_name, &:read)
      end
    end

    describe "key rotation" do
      it "reads values encrypted by the previous cipher" do
        previous_value = the_previous_cipher.encrypt(clear_value)

        assert_equal clear_value, SymmetricEncryption.decrypt(previous_value)
      end

      it "encrypts new values with the authenticated cipher" do
        encrypted = SymmetricEncryption.encrypt(clear_value)

        assert_equal the_cipher.version, SymmetricEncryption.header(encrypted).version
        assert_equal clear_value, SymmetricEncryption.decrypt(encrypted)
      end

      it "reads a headerless value from the previous cipher when the version is supplied" do
        headerless = the_previous_cipher.encrypt(clear_value, header: false)

        assert_equal clear_value, SymmetricEncryption.decrypt(headerless, version: the_previous_cipher.version)
      end
    end
  end
end
