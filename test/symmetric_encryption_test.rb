require_relative "test_helper"

# Unit Test for SymmetricEncryption
#
class SymmetricEncryptionTest < Minitest::Test
  describe "SymmetricEncryption" do
    describe "configuration" do
      before do
        config = SymmetricEncryption::Config.new(
          file_name: File.join(File.dirname(__FILE__), "config", "symmetric-encryption.yml"),
          env:       "test"
        )
        @ciphers = config.ciphers

        @cipher_v2, @cipher_v6, @cipher_v1, @cipher_v0 = @ciphers
      end

      it "matches config file for first cipher" do
        cipher = SymmetricEncryption.cipher

        assert @cipher_v2.send(:key)
        assert @cipher_v2.send(:iv)
        assert @cipher_v2.version
        assert_equal @cipher_v2.cipher_name, cipher.cipher_name
        assert_equal @cipher_v2.version, cipher.version
        refute_includes SymmetricEncryption.secondary_ciphers, cipher
      end

      it "match config file for v1 cipher" do
        cipher = SymmetricEncryption.cipher(2)

        assert @cipher_v2.cipher_name
        assert @cipher_v2.version
        assert_equal @cipher_v2.cipher_name, cipher.cipher_name
        assert_equal @cipher_v2.version, cipher.version
        refute_includes SymmetricEncryption.secondary_ciphers, cipher
      end

      it "match config file for v0 cipher" do
        cipher = SymmetricEncryption.cipher(0)

        assert @cipher_v0.cipher_name
        assert @cipher_v0.version
        assert_equal @cipher_v0.cipher_name, cipher.cipher_name
        assert_equal @cipher_v0.version, cipher.version
        assert_includes SymmetricEncryption.secondary_ciphers, cipher
      end
    end

    %i[none base64 base64strict base64urlsafe base16].each do |encoding|
      describe "encoding: #{encoding}" do
        before do
          @social_security_number             = "987654321"
          @social_security_number_encrypted   =
            case encoding
            when :base64
              "QEVuQwIAS+8X1NRrqdfEIQyFHVPuVA==\n"
            when :base64strict
              "QEVuQwIAS+8X1NRrqdfEIQyFHVPuVA=="
            when :base64urlsafe
              "QEVuQwIAS-8X1NRrqdfEIQyFHVPuVA=="
            when :base16
              "40456e4302004bef17d4d46ba9d7c4210c851d53ee54"
            when :none
              "@EnC\x02\x00K\xEF\x17\xD4\xD4k\xA9\xD7\xC4!\f\x85\x1DS\xEET".b
            else
              raise "Add test for encoding: #{encoding}"
            end
          @non_utf8                           = "\xc2".b
          @encoding                           = SymmetricEncryption.cipher.encoding
          SymmetricEncryption.cipher.encoding = encoding
        end

        after do
          SymmetricEncryption.cipher.encoding = @encoding
        end

        it "encrypt simple string" do
          assert_equal @social_security_number_encrypted, SymmetricEncryption.encrypt(@social_security_number)
        end

        it "decrypt string" do
          assert decrypted = SymmetricEncryption.decrypt(@social_security_number_encrypted)
          assert_equal @social_security_number, decrypted
          assert_equal Encoding.find("utf-8"), decrypted.encoding, decrypted
        end

        it "return BINARY encoding for non-UTF-8 encrypted data" do
          assert_equal Encoding.find("binary"), @non_utf8.encoding
          assert_predicate @non_utf8, :valid_encoding?
          assert encrypted = SymmetricEncryption.encrypt(@non_utf8)
          assert decrypted = SymmetricEncryption.decrypt(encrypted)
          assert_predicate decrypted, :valid_encoding?
          assert_equal Encoding.find("binary"), decrypted.encoding, decrypted
          assert_equal @non_utf8, decrypted
        end

        it "return nil when encrypting nil" do
          assert_nil SymmetricEncryption.encrypt(nil)
        end

        it "return '' when encrypting ''" do
          assert_equal "", SymmetricEncryption.encrypt("")
        end

        it "return nil when decrypting nil" do
          assert_nil SymmetricEncryption.decrypt(nil)
        end

        it "return '' when decrypting ''" do
          assert_equal "", SymmetricEncryption.decrypt("")
        end

        it "determine if string is encrypted" do
          if %i[base64strict base64urlsafe base64].include?(encoding)
            assert SymmetricEncryption.encrypted?(@social_security_number_encrypted)
            refute SymmetricEncryption.encrypted?(@social_security_number)

            # Without a header it can only assume it is not encrypted
            refute SymmetricEncryption.encrypted?(SymmetricEncryption.encrypt(@social_security_number, header: false))
          end
        end
      end
    end

    describe "using select_cipher" do
      before do
        @social_security_number = "987654321"
        # Encrypt data without a header and encode with base64 which has a trailing '\n'
        no_header = SymmetricEncryption.cipher(0).binary_encrypt(@social_security_number, header: false)
        @encrypted_0_ssn = SymmetricEncryption.cipher(0).encode(no_header)

        SymmetricEncryption.select_cipher do |encoded_str, _decoded_str|
          # Use cipher version 0 if the encoded string ends with "\n" otherwise
          # use the current default cipher
          encoded_str.end_with?("\n") ? SymmetricEncryption.cipher(0) : SymmetricEncryption.cipher
        end
      end

      after do
        # Clear out select_cipher
        SymmetricEncryption.select_cipher
      end

      it "decrypt string without a header using an old cipher" do
        assert_equal @social_security_number, SymmetricEncryption.decrypt(@encrypted_0_ssn)
      end
    end

    describe "without select_cipher" do
      before do
        @social_security_number = "987654321"
        # Encrypt data without a header and encode with base64 which has a trailing '\n'
        no_header = SymmetricEncryption.cipher(0).binary_encrypt(@social_security_number, header: false)

        assert @encrypted_0_ssn = SymmetricEncryption.cipher(0).encode(no_header)
      end

      it "decrypt string without a header using an old cipher" do
        assert_raises OpenSSL::Cipher::CipherError do
          SymmetricEncryption.decrypt(@encrypted_0_ssn)
        end
      end
    end

    describe "random iv" do
      before do
        @social_security_number = "987654321"
      end

      it "encrypt and then decrypt using random iv" do
        # Encrypt with random iv
        assert encrypted = SymmetricEncryption.encrypt(@social_security_number, random_iv: true)
        assert_equal @social_security_number, SymmetricEncryption.decrypt(encrypted)
      end

      it "encrypt and then decrypt using random iv with higher version" do
        # Encrypt with random iv
        assert encrypted = SymmetricEncryption.cipher(6).encrypt(@social_security_number, random_iv: true)
        assert_equal @social_security_number, SymmetricEncryption.decrypt(encrypted)
      end

      it "encrypt and then decrypt using random iv with compression" do
        # Encrypt with random iv and compress
        assert encrypted = SymmetricEncryption.encrypt(@social_security_number, random_iv: true, compress: true)
        assert_equal @social_security_number, SymmetricEncryption.decrypt(encrypted)
      end
    end

    describe "data types" do
      describe "string" do
        before do
          @social_security_number = "987654321"
        end

        it "encrypt and decrypt value to and from a string" do
          assert encrypted = SymmetricEncryption.encrypt(@social_security_number, type: :string)
          assert_equal @social_security_number, SymmetricEncryption.decrypt(encrypted, type: :string)
        end

        it "retains empty" do
          encrypted = SymmetricEncryption.encrypt("", type: :string)

          assert_equal "", encrypted
          assert_equal "", SymmetricEncryption.decrypt(encrypted, type: :string)
        end

        it "retains nil" do
          assert_nil encrypted = SymmetricEncryption.encrypt(nil, type: :string)
          assert_nil SymmetricEncryption.decrypt(encrypted, type: :string)
        end
      end

      {
        integer:  21,
        float:    2.5,
        decimal:  BigDecimal("12.58"),
        datetime: DateTime.new(2001, 11, 26, 20, 55, 54, "-5"),
        time:     Time.new(2013, 1, 1, 22, 30, 0, "-04:00"),
        date:     Date.new(1927, 4, 1),
        boolean:  true,
        yaml:     {a: :b},
        json:     {"a" => "b"}
      }.each_pair do |type, value|
        describe type.to_s do
          it "encrypt and decrypt" do
            assert encrypted = SymmetricEncryption.encrypt(value, type: type)
            assert_equal value, SymmetricEncryption.decrypt(encrypted, type: type)
          end

          it "retains nil" do
            assert_nil encrypted = SymmetricEncryption.encrypt(nil, type: type)
            assert_nil SymmetricEncryption.decrypt(encrypted, type: type)
          end
        end
      end

      describe "boolean false" do
        it "encrypt and decrypt" do
          assert encrypted = SymmetricEncryption.encrypt(false, type: :boolean)
          # The point is the exact value, not truthiness: :boolean must coerce back to false.
          assert_equal false, SymmetricEncryption.decrypt(encrypted, type: :boolean) # rubocop:disable Minitest/RefuteFalse
        end
      end
    end

    describe ".cipher=" do
      it "rejects an object that cannot encrypt and decrypt" do
        assert_raises(ArgumentError) { SymmetricEncryption.cipher = "not a cipher" }
      end

      it "permits nil" do
        previous = SymmetricEncryption.cipher
        SymmetricEncryption.cipher = nil

        refute_predicate SymmetricEncryption, :cipher?
      ensure
        SymmetricEncryption.cipher = previous
      end

      it "raises when encrypting before a cipher is set" do
        previous = SymmetricEncryption.cipher
        SymmetricEncryption.cipher = nil

        assert_raises(SymmetricEncryption::ConfigError) { SymmetricEncryption.encrypt("Hello World") }
      ensure
        SymmetricEncryption.cipher = previous
      end
    end

    describe ".secondary_ciphers=" do
      it "rejects a value that is not a collection" do
        assert_raises(ArgumentError) { SymmetricEncryption.secondary_ciphers = :not_a_collection }
      end

      it "rejects a collection of non ciphers" do
        assert_raises(ArgumentError) { SymmetricEncryption.secondary_ciphers = ["not a cipher"] }
      end
    end

    describe ".randomize_iv=" do
      it "changes the default for encrypt" do
        previous = SymmetricEncryption.randomize_iv?
        SymmetricEncryption.randomize_iv = true

        assert_predicate SymmetricEncryption, :randomize_iv?
        refute_equal SymmetricEncryption.encrypt("Hello World"), SymmetricEncryption.encrypt("Hello World")
      ensure
        SymmetricEncryption.randomize_iv = previous
      end
    end

    describe ".decrypt" do
      it "uses the supplied version when there is no header" do
        cipher    = SymmetricEncryption.cipher(6)
        encrypted = cipher.encrypt("Hello World", header: false)

        assert_equal "Hello World", SymmetricEncryption.decrypt(encrypted, version: 6)
      end

      # Applications that enable frozen string literals pass frozen values in.
      %i[none base64 base64strict base64urlsafe base16].each do |encoding|
        it "accepts a frozen value with encoding: #{encoding}" do
          previous                            = SymmetricEncryption.cipher.encoding
          SymmetricEncryption.cipher.encoding = encoding
          begin
            encrypted = SymmetricEncryption.encrypt("Hello World").freeze

            assert_equal "Hello World", SymmetricEncryption.decrypt(encrypted)
          ensure
            SymmetricEncryption.cipher.encoding = previous
          end
        end
      end
    end

    describe ".encrypted?" do
      it "accepts a frozen value" do
        assert SymmetricEncryption.encrypted?(SymmetricEncryption.encrypt("Hello World").freeze)
      end

      # The magic header depends on the encoding of the primary cipher, so it must not be
      # memoized at module level: `cipher=` and every `Config.load!` replace that cipher.
      it "follows the primary cipher when it is replaced" do
        original = SymmetricEncryption.cipher
        begin
          assert SymmetricEncryption.encrypted?(SymmetricEncryption.encrypt("Hello World"))

          SymmetricEncryption.cipher = SymmetricEncryption::Cipher.new(
            key:               "ABCDEF1234567890",
            iv:                "ABCDEF1234567890",
            cipher_name:       "aes-128-cbc",
            encoding:          :base16,
            always_add_header: true
          )

          assert SymmetricEncryption.encrypted?(SymmetricEncryption.encrypt("Hello World"))
        ensure
          SymmetricEncryption.cipher = original
        end
      end

      # Same reason, reached through the cipher rather than by replacing it.
      it "follows the encoding of the primary cipher when it changes" do
        previous = SymmetricEncryption.cipher.encoding
        begin
          assert SymmetricEncryption.encrypted?(SymmetricEncryption.encrypt("Hello World"))

          SymmetricEncryption.cipher.encoding = previous == :base16 ? :base64 : :base16

          assert SymmetricEncryption.encrypted?(SymmetricEncryption.encrypt("Hello World"))
        ensure
          SymmetricEncryption.cipher.encoding = previous
        end
      end
    end

    describe ".try_decrypt" do
      it "returns nil when the value cannot be decrypted" do
        assert_nil SymmetricEncryption.try_decrypt("Not an encrypted value")
      end

      it "decrypts a valid value" do
        assert_equal "Hello World", SymmetricEncryption.try_decrypt(SymmetricEncryption.encrypt("Hello World"))
      end
    end

    describe ".random_password" do
      it "defaults to 22 bytes of randomness" do
        assert_equal 30, SymmetricEncryption.random_password.length
      end

      it "is url safe" do
        assert_match(/\A[A-Za-z0-9\-_]+\z/, SymmetricEncryption.random_password)
      end

      it "generates a different password every time" do
        refute_equal SymmetricEncryption.random_password, SymmetricEncryption.random_password
      end
    end
  end
end
