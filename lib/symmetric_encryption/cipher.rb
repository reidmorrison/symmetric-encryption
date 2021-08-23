require "openssl"
module SymmetricEncryption
  # Hold all information related to encryption keys
  # as well as encrypt and decrypt data using those keys.
  #
  # Cipher is thread safe so that the same instance can be called by multiple
  # threads at the same time without needing an instance of Cipher per thread.
  class Cipher
    # Cipher to use for encryption and decryption
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
    #       Return as a base64 encoded string that does not include additional newlines
    #       This is the recommended format since newlines in the values to
    #       SQL queries are cumbersome. Also the newline reformatting is unnecessary
    #       It is not the default for backward compatibility
    #     :base64urlsafe
    #       Same as base64strict except that base64urlsafe uses '-' instead of '+' and '_' instead of '/'.
    #     :base64
    #       Return as a base64 encoded string
    #     :base16
    #       Return as a Hex encoded string
    #     :none
    #       Return as raw binary data string. Note: String can contain embedded nulls
    #     Default: :base64strict
    #
    #   version [Integer]
    #     Optional. The version number of this encryption key
    #     Used by SymmetricEncryption to select the correct key when decrypting data
    #     Valid Range: 0..255
    #     Default: 1
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

      @key               = key
      @iv                = iv
      @cipher_name       = cipher_name
      self.encoding      = encoding.to_sym
      @version           = version.to_i
      @always_add_header = always_add_header

      return unless (@version > 255) || @version.negative?

      raise(ArgumentError, "Cipher version has a valid range of 0 to 255. #{@version} is too high, or negative")
    end

    # Change the encoding
    def encoding=(encoding)
      @encoder  = nil
      @encoding = encoding
    end

    # Returns [SymmetricEncryption::Encoder] the encoder to use for the current encoding.
    def encoder
      @encoder ||= SymmetricEncryption::Encoder[encoding]
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
    #     Default: false
    #     Highly Recommended where feasible: true
    #
    #   compress [true|false]
    #     Whether to compress str before encryption.
    #     Default: false
    #     Notes:
    #     * Should only be used for large strings since compression overhead and
    #       the overhead of adding the encryption header may exceed any benefits of
    #       compression
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
    #   Returns nil if encrypted_string is nil
    #   Returns '' if encrypted_string == ''
    #
    # Parameters
    #   encrypted_string [String]
    #     Binary encrypted string to decrypt
    #
    # Reads the header if present for key, iv, cipher_name and compression
    #
    # encrypted_string must be in raw binary form when calling this method
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
    #     Whether the encypted value should use a random IV every time the
    #     field is encrypted.
    #     Notes:
    #     * Setting random_iv to true will result in a different encrypted output for
    #       the same input string.
    #     * It is recommended to set this to true, except if it will be used as a lookup key.
    #     * Only set to true if the field will never be used as a lookup key, since
    #       the encrypted value needs to be same every time in this case.
    #     * When random_iv is true it adds the random IV string to the header.
    #     Default: false
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
    # encrypted_string must be in raw binary form when calling this method
    #
    # Creates a new OpenSSL::Cipher with every call so that this call
    # is thread-safe and can be called concurrently by multiple threads with
    # the same instance of Cipher
    #
    # Note:
    #   When a string is encrypted and the header is used, its decrypted form
    #   is automatically set to the same UTF-8 or Binary encoding
    def binary_decrypt(encrypted_string, header: Header.new)
      return if encrypted_string.nil?

      str = encrypted_string.to_s
      str.force_encoding(SymmetricEncryption::BINARY_ENCODING)
      return str if str.empty?

      offset = header.parse(str)
      data   = offset.positive? ? str[offset..-1] : str

      openssl_cipher = ::OpenSSL::Cipher.new(header.cipher_name || cipher_name)
      openssl_cipher.decrypt
      openssl_cipher.key = header.key || @key
      if (iv = header.iv || @iv)
        openssl_cipher.iv = iv
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
      "#<#{self.class}:0x#{__id__.to_s(16)} @key=\"[FILTERED]\" @iv=#{iv.inspect} @cipher_name=#{cipher_name.inspect}, @version=#{version.inspect}, @encoding=#{encoding.inspect}, @always_add_header=#{always_add_header.inspect}>"
    end

    # DEPRECATED
    def self.has_header?(buffer)
      SymmetricEncryption::Header.present?(buffer)
    end

    # DEPRECATED
    def self.parse_header!(buffer)
      header = SymmetricEncryption::Header.new
      header.parse!(buffer) ? header : nil
    end

    # DEPRECATED
    def self.build_header(version, compress = false, iv = nil, key = nil, cipher_name = nil)
      h = Header.new(version: version, compress: compress, iv: iv, key: key, cipher_name: cipher_name)
      h.to_s
    end

    private

    attr_reader :key
  end
end
