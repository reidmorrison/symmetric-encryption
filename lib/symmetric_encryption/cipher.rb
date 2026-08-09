require "openssl"
module SymmetricEncryption
  # Hold all information related to encryption keys
  # as well as encrypt and decrypt data using those keys.
  #
  # Cipher is thread safe so that the same instance can be called by multiple
  # threads at the same time without needing an instance of Cipher per thread.
  class Cipher
    # cipher_name: [String] the OpenSSL cipher, for example `aes-256-cbc`.
    # version:     [Integer] which of the configured ciphers this is, written into the header.
    # iv:          [String|nil] the fixed iv, used when the value is encrypted without a random iv.
    # always_add_header: [true|false] whether to add the header when nothing else requires it.
    attr_accessor :cipher_name, :version, :iv, :always_add_header
    attr_reader :encoding
    attr_writer :key

    # Returns [Cipher] from a cipher config instance.
    def self.from_config(cipher_name: "aes-256-cbc",
                         version: 0,
                         always_add_header: true,
                         encoding: :base64strict,
                         **config)
      Keystore.migrate_config!(config)
      key = Keystore.read_key(cipher_name: cipher_name, **config)

      Cipher.new(
        key:               key.key,
        iv:                key.iv,
        cipher_name:       cipher_name,
        version:           version,
        always_add_header: always_add_header,
        encoding:          encoding
      )
    end

    # Returns [SymmetricEncryption::Cipher] for encryption and decryption purposes.
    #
    # Parameters:
    #   key [String]
    #     The Symmetric Key to use for encryption and decryption.
    #
    #   iv [String]
    #     The Initialization Vector to use.
    #
    #   cipher_name [String]
    #     Optional. Encryption Cipher to use
    #     Default: aes-256-cbc
    #
    #   encoding [Symbol]
    #     :base64strict
    #       Return as a base64 encoded string that does not include additional newlines.
    #       This is the recommended format, and the default, since newlines in the values in
    #       SQL queries are cumbersome, and the newline reformatting is unnecessary.
    #     :base64urlsafe
    #       Same as base64strict except that base64urlsafe uses '-' instead of '+' and '_' instead of '/'.
    #     :base64
    #       Return as a base64 encoded string, with a newline every 60 characters.
    #     :base16
    #       Return as a Hex encoded string
    #     :none
    #       Return as raw binary data string. Note: String can contain embedded nulls
    #     Default: :base64strict
    #     Note: Every cipher in one configuration file has to use an encoding that the others can
    #       read, since a value is decoded with the primary cipher's encoder before its header
    #       says which cipher encrypted it. See `Config#validate_encodings!`.
    #
    #   version [Integer]
    #     Optional. The version number of this encryption key
    #     Used by SymmetricEncryption to select the correct key when decrypting data
    #     Valid Range: 0..255
    #     Default: 0
    #
    #   always_add_header [true|false]
    #     Whether to always include the header when encrypting data.
    #     ** Highly recommended to set this value to true **
    #     Increases the length of the encrypted data by a few bytes, but makes
    #     migration to a new key trivial
    #     Default: true
    def initialize(key:,
                   iv: nil,
                   cipher_name: "aes-256-cbc",
                   version: 0,
                   always_add_header: true,
                   encoding: :base64strict)
      openssl_cipher     = ::OpenSSL::Cipher.new(cipher_name)
      @key               = Key.binary!(key, length: openssl_cipher.key_len, cipher_name: cipher_name, name: "key")
      @iv                = iv && Key.binary!(iv, length: openssl_cipher.iv_len, cipher_name: cipher_name, name: "iv")
      @cipher_name       = cipher_name
      self.encoding      = encoding.to_sym
      @version           = version.to_i
      @always_add_header = always_add_header
      @authenticated     = openssl_cipher.authenticated?
      @iv_length         = openssl_cipher.iv_len

      return unless (@version > 255) || @version.negative?

      raise(ArgumentError, "Cipher version has a valid range of 0 to 255. #{@version} is too high, or negative")
    end

    # Change the encoding
    def encoding=(encoding)
      # Both are derived from the encoding, so they have to be discarded along with it.
      @encoder              = nil
      @encoded_magic_header = nil
      @encoding             = encoding
    end

    # Returns [SymmetricEncryption::Encoder] the encoder to use for the current encoding.
    def encoder
      @encoder ||= SymmetricEncryption::Encoder[encoding]
    end

    # Returns [true|false] whether this cipher is an authenticated cipher, such as `aes-256-gcm`.
    #
    # An authenticated cipher detects any change to the encrypted value, instead of returning
    # data that was decrypted from something that had been tampered with. It produces an auth
    # tag when encrypting, which has to be supplied again to decrypt, so encrypted values always
    # carry a header, whatever `always_add_header` is set to.
    #
    # Notes:
    # * A configured `iv` is not used by an authenticated cipher. Every encrypted value gets its
    #   own iv, since re-using one across different values would expose the data. With
    #   `random_iv: false` the iv is derived from the value being encrypted, so that encrypting
    #   the same value twice still returns the same encrypted value. See `#deterministic_iv`.
    # * `Writer` and `Reader` support authenticated ciphers. A stream larger than one chunk is
    #   written as a chunked stream, so that it is verified as it is read rather than only once
    #   all of it has been read. See `SymmetricEncryption::ChunkedStream`.
    def authenticated?
      @authenticated
    end

    # Encrypt and then encode a string
    #
    # Returns data encrypted and then encoded according to the encoding setting
    #         of this cipher
    # Returns nil if str is nil
    # Returns "" str is empty
    #
    # Parameters
    #
    #   str [String]
    #     String to be encrypted. If str is not a string, #to_s will be called on it
    #     to convert it to a string
    #
    #   random_iv [true|false]
    #     Whether the encrypted value should use a random IV every time the
    #     field is encrypted.
    #     Notes:
    #     * Setting random_iv to true will result in a different encrypted output for
    #       the same input string.
    #     * It is recommended to set this to true, except if it will be used as a lookup key.
    #     * Only set to true if the field will never be used as a lookup key, since
    #       the encrypted value needs to be same every time in this case.
    #     * When random_iv is true it adds the random IV string to the header.
    #     Default: `SymmetricEncryption.randomize_iv?`
    #     Highly Recommended where feasible: true
    #
    #   compress [true|false]
    #     Whether to compress str before encryption.
    #     Default: false
    #     Notes:
    #     * Should only be used for large strings since compression overhead and
    #       the overhead of adding the encryption header may exceed any benefits of
    #       compression
    #
    #   header [true|false]
    #     Whether to add the header to the encrypted value. A header is added regardless when it
    #     is needed to decrypt the value again: when random_iv or compress is true, or when this
    #     is an authenticated cipher.
    #     Default: `always_add_header`
    def encrypt(str, random_iv: SymmetricEncryption.randomize_iv?, compress: false, header: always_add_header)
      return if str.nil?

      str = str.to_s
      return str if str.empty?

      encrypted = binary_encrypt(str, random_iv: random_iv, compress: compress, header: header)
      encode(encrypted)
    end

    # Decode and Decrypt string
    #   Returns a decrypted string after decoding it first according to the
    #           encoding setting of this cipher
    #   Returns nil if str is nil
    #   Returns '' if str == ''
    #
    # Parameters
    #   str [String]
    #     Encoded, encrypted string to decode and decrypt.
    #
    # Reads the header if present for key, iv, cipher_name and compression.
    #
    # Note: This always decrypts with _this_ cipher. Only `SymmetricEncryption.decrypt` looks the
    #       cipher up by the version in the header.
    #
    # Creates a new OpenSSL::Cipher with every call so that this call
    # is thread-safe and can be called concurrently by multiple threads with
    # the same instance of Cipher
    def decrypt(str)
      decoded = decode(str)
      return unless decoded

      return decoded if decoded.empty?

      decrypted = binary_decrypt(decoded)

      # Try to force result to UTF-8 encoding, but if it is not valid, force it back to Binary
      unless decrypted.force_encoding(SymmetricEncryption::UTF8_ENCODING).valid_encoding?
        decrypted.force_encoding(SymmetricEncryption::BINARY_ENCODING)
      end

      decrypted
    end

    # Returns UTF8 encoded string after encoding the supplied Binary string
    #
    # Encode the supplied string using the encoding in this cipher instance
    # Returns nil if the supplied string is nil
    # Note: No encryption or decryption is performed
    #
    # Returned string is UTF8 encoded except for encoding :none
    def encode(binary_string)
      return binary_string if binary_string.nil? || (binary_string == "")

      encoder.encode(binary_string)
    end

    # Decode the supplied string using the encoding in this cipher instance
    # Note: No encryption or decryption is performed
    #
    # Returned string is Binary encoded
    def decode(encoded_string)
      return encoded_string if encoded_string.nil? || (encoded_string == "")

      encoder.decode(encoded_string)
    end

    # Return a new random key using the configured cipher_name
    # Useful for generating new symmetric keys
    def random_key
      ::OpenSSL::Cipher.new(cipher_name).random_key
    end

    # Return a new random IV using the configured cipher_name
    # Useful for generating new symmetric keys
    def random_iv
      ::OpenSSL::Cipher.new(cipher_name).random_iv
    end

    # Returns the block size for the configured cipher_name
    def block_size
      ::OpenSSL::Cipher.new(cipher_name).block_size
    end

    # Advanced use only
    #
    # Returns a Binary encrypted string without applying Base64, or any other encoding.
    #
    #   str [String]
    #     String to be encrypted. If str is not a string, #to_s will be called on it
    #     to convert it to a string
    #
    #   random_iv [true|false]
    #     Whether the encrypted value should use a random IV every time the
    #     field is encrypted.
    #     Notes:
    #     * Setting random_iv to true will result in a different encrypted output for
    #       the same input string.
    #     * It is recommended to set this to true, except if it will be used as a lookup key.
    #     * Only set to true if the field will never be used as a lookup key, since
    #       the encrypted value needs to be same every time in this case.
    #     * When random_iv is true it adds the random IV string to the header.
    #     Default: `SymmetricEncryption.randomize_iv?`
    #     Highly Recommended where feasible: true
    #
    #   compress [true|false]
    #     Whether to compress str before encryption.
    #     Default: false
    #     Notes:
    #     * Should only be used for large strings since compression overhead and
    #       the overhead of adding the encryption header may exceed any benefits of
    #       compression
    #
    #   header [true|false]
    #     Whether to add a header to the encrypted string.
    #     Default: `always_add_header`
    #
    # See #encrypt to encrypt and encode the result as a string.
    def binary_encrypt(str, random_iv: SymmetricEncryption.randomize_iv?, compress: false, header: always_add_header)
      return if str.nil?

      string = str.to_s
      return string if string.empty?

      return authenticated_binary_encrypt(string, random_iv: random_iv, compress: compress) if authenticated?

      # Header required when adding a random_iv or compressing
      header = Header.new(version: version, compress: compress) if header || random_iv || compress

      # Creates a new OpenSSL::Cipher with every call so that this call is thread-safe.
      openssl_cipher = ::OpenSSL::Cipher.new(cipher_name)
      openssl_cipher.encrypt
      openssl_cipher.key = @key

      result =
        if header
          if random_iv
            openssl_cipher.iv = header.iv = openssl_cipher.random_iv
          elsif iv
            openssl_cipher.iv = iv
          end
          header.to_s + openssl_cipher.update(compress ? Zlib::Deflate.deflate(string) : string)
        else
          openssl_cipher.iv = iv if iv
          openssl_cipher.update(string)
        end
      result << openssl_cipher.final
    end

    # Advanced use only
    # See #decrypt to decrypt encoded strings
    #
    # Returns a Binary decrypted string without decoding the string first
    # The returned string has BINARY encoding
    #
    # Decryption of supplied string
    #   Returns the decrypted string
    #   Returns nil if encrypted_string is nil
    #   Returns '' if encrypted_string == ''
    #
    # Parameters
    #   encrypted_string [String]
    #     Binary encrypted string to decrypt
    #
    #   header [SymmetricEncryption::Header]
    #     Optional header for the supplied encrypted_string
    #
    # Reads the 'magic' header if present for key, iv, cipher_name and compression
    #
    # encrypted_string must already be decoded. It does not have to carry the BINARY encoding,
    # a binary copy is taken when it does not, since the header offsets are byte offsets.
    #
    # Creates a new OpenSSL::Cipher with every call so that this call
    # is thread-safe and can be called concurrently by multiple threads with
    # the same instance of Cipher
    #
    # Note:
    #   The result is always BINARY encoded. `#decrypt` is what forces it to UTF-8 when the
    #   decrypted bytes are valid UTF-8.
    def binary_decrypt(encrypted_string, header: Header.new)
      return if encrypted_string.nil?

      # The offset returned by the header is a byte offset, so the string has to be binary for
      # the slice below to cut in the same units. Convert a copy when it is not already binary,
      # rather than re-encoding the caller's string in place.
      str = encrypted_string.to_s
      str = str.b unless str.encoding == SymmetricEncryption::BINARY_ENCODING
      return str if str.empty?

      offset = header.parse(str)
      data   = offset.positive? ? str[offset..] : str

      openssl_cipher = ::OpenSSL::Cipher.new(header.cipher_name || cipher_name)
      openssl_cipher.decrypt
      # Before the key and the iv, so that a value that disagrees with the cipher about whether it
      # is authenticated is reported as such, rather than as whatever the mismatch breaks first.
      verify_authentication!(openssl_cipher, header)
      openssl_cipher.key = header.key || @key
      if (iv = header.iv || @iv)
        openssl_cipher.iv = iv
      end
      # After the key and the iv, which OpenSSL requires to be set first.
      if openssl_cipher.authenticated?
        openssl_cipher.auth_tag  = header.auth_tag
        openssl_cipher.auth_data = header.auth_data
      end
      result = openssl_cipher.update(data)
      result << openssl_cipher.final
      header.compressed? ? Zlib::Inflate.inflate(result) : result
    end

    # Returns the magic header after applying the encoding in this cipher
    def encoded_magic_header
      @encoded_magic_header ||= encoder.encode(SymmetricEncryption::Header::MAGIC_HEADER).delete("=").strip
    end

    # Returns [String] object represented as a string, filtering out the key
    def inspect
      "#<#{self.class}:0x#{__id__.to_s(16)} @key=\"[FILTERED]\" @iv=#{iv.inspect} " \
        "@cipher_name=#{cipher_name.inspect}, @version=#{version.inspect}, " \
        "@encoding=#{encoding.inspect}, @always_add_header=#{always_add_header.inspect}>"
    end

    # DEPRECATED
    def self.has_header?(buffer) # rubocop:disable Naming/PredicatePrefix
      SymmetricEncryption::Header.present?(buffer)
    end

    # DEPRECATED
    def self.parse_header!(buffer)
      header = SymmetricEncryption::Header.new
      header.parse!(buffer) ? header : nil
    end

    # DEPRECATED
    # rubocop:disable Metrics/ParameterLists, Style/OptionalBooleanParameter
    def self.build_header(version, compress = false, iv = nil, key = nil, cipher_name = nil)
      # rubocop:enable Metrics/ParameterLists, Style/OptionalBooleanParameter
      h = Header.new(version: version, compress: compress, iv: iv, key: key, cipher_name: cipher_name)
      h.to_s
    end

    private

    attr_reader :key

    # Encrypt with an authenticated cipher, such as `aes-256-gcm`.
    #
    # The auth tag is only known once the data has been encrypted, and it is carried in the
    # header, so the data is encrypted first and the header is built around it afterwards.
    def authenticated_binary_encrypt(string, random_iv:, compress:)
      header = Header.new(version: version, compress: compress, authenticated: true)

      # Creates a new OpenSSL::Cipher with every call so that this call is thread-safe.
      openssl_cipher = ::OpenSSL::Cipher.new(cipher_name)
      openssl_cipher.encrypt
      openssl_cipher.key = @key
      header.iv          = openssl_cipher.iv = random_iv ? openssl_cipher.random_iv : deterministic_iv(string)

      # Covers the header, so that the version, the flags, the iv and the cipher name cannot be
      # changed without the auth tag check failing when the value is decrypted.
      openssl_cipher.auth_data = header.auth_data

      encrypted = openssl_cipher.update(compress ? Zlib::Deflate.deflate(string) : string)
      encrypted << openssl_cipher.final
      header.auth_tag = openssl_cipher.auth_tag(Header::AUTH_TAG_SIZE)

      header.to_s + encrypted
    end

    # Returns [String] an iv derived from the value being encrypted, so that encrypting the same
    # value twice returns the same encrypted value, which is what `random_iv: false` asks for.
    #
    # Re-using one iv across _different_ values would be far worse for an authenticated cipher
    # than it is for `aes-256-cbc`: it exposes the encrypted data and makes the auth tag
    # forgeable. Deriving the iv from the value means a repeated iv only ever accompanies
    # repeated data, which is what was asked for. Active Record encryption derives the iv the
    # same way for its deterministic attributes.
    def deterministic_iv(string)
      ::OpenSSL::HMAC.digest("SHA256", @key, string)[0, @iv_length]
    end

    # Rejects a value whose header does not agree with the cipher about whether it is
    # authenticated. Without this an attacker could strip the auth tag, or name an
    # unauthenticated cipher in the header, and have the value decrypted without being checked.
    def verify_authentication!(openssl_cipher, header)
      return if openssl_cipher.authenticated? == header.authenticated?

      name = (header.cipher_name || cipher_name).inspect
      if openssl_cipher.authenticated?
        raise(
          SymmetricEncryption::CipherError,
          "Cipher #{name} is an authenticated cipher, but the encrypted value has no auth tag. Data encrypted " \
          "with an unauthenticated cipher has to be decrypted with the cipher that encrypted it. Keep that cipher " \
          "in `symmetric-encryption.yml` as a secondary cipher, so that it is selected by the version in the " \
          "header of the values it encrypted."
        )
      end

      raise(
        SymmetricEncryption::CipherError,
        "The encrypted value has an auth tag, but #{name} is not an authenticated cipher, so the tag cannot be " \
        "verified."
      )
    end
  end
end
