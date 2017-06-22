require 'openssl'
module SymmetricEncryption
  # Hold all information related to encryption keys
  # as well as encrypt and decrypt data using those keys
  #
  # Cipher is thread safe so that the same instance can be called by multiple
  # threads at the same time without needing an instance of Cipher per thread
  class Cipher
    # Cipher to use for encryption and decryption
    attr_accessor :cipher_name, :version, :iv, :always_add_header
    attr_reader :encoding, :key_filename, :iv_filename, :key_encryption_key, :key_env_var
    attr_writer :key

    # Create a Symmetric::Cipher for encryption and decryption purposes
    #
    # Parameters:
    #   key [String]
    #     The Symmetric Key to use for encryption and decryption.
    #     Default: :random, generate a new random key if `key_filename` or `encrypted_key` is not supplied.
    #  Or,
    #   key_filename
    #     Name of file containing symmetric key encrypted using the key encryption key.
    #  Or,
    #   encrypted_key
    #     Symmetric key encrypted using key encryption key and then encoded with supplied `encoding`.
    #  Or,
    #   key_env_var [String]
    #     Name of the environment variable from which to read the encrypted encryption key.
    #
    #   iv [String]
    #     Optional. The Initialization Vector to use with Symmetric Key.
    #     Highly Recommended as it is the input into the CBC algorithm.
    #     Default: :random, generate a new random IV if `iv_filename` or `encrypted_iv` is not supplied.
    #  Or,
    #   iv_filename
    #     Name of file containing the IV (initialization vector) encrypted using the key encryption key.
    #     DEPRECATED: It is _not_ necessary to encrypt the initialization vector (IV).
    #  Or,
    #   encrypted_iv
    #     IV (initialization vector) encrypted using key encryption key and then encoded with supplied `encoding`.
    #     DEPRECATED: It is _not_ necessary to encrypt the initialization vector (IV).
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
    #     :base64
    #       Return as a base64 encoded string
    #     :base16
    #       Return as a Hex encoded string
    #     :none
    #       Return as raw binary data string. Note: String can contain embedded nulls
    #     Default: :base64strict
    #
    #   version [Fixnum]
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
    #
    #   private_rsa_key [String]
    #     Key encryption key.
    #     To generate a new one: SymmetricEncryption::KeyEncryptionKey.generate
    #     Required if :key_filename, :encrypted_key, :iv_filename, or :encrypted_iv is supplied
    #
    #   key_encryption_key [SymmetricEncryption::KeyEncryptionKey]
    #     Key encryption key to encrypt/decrypt the key and/or iv with.
    #     Note:
    #     - `private_rsa_key` is not used if `key_encryption_key` is supplied.
    def initialize(cipher_name: 'aes-256-cbc',
                   encoding: :base64strict,
                   version: 0,
                   always_add_header: true,
                   private_rsa_key: nil, key_encryption_key: nil,
                   key_filename: nil, encrypted_key: nil, key: :random, key_env_var: nil,
                   iv_filename: nil, encrypted_iv: nil, iv: :random)

      @cipher_name       = cipher_name
      self.encoding      = encoding.to_sym
      @version           = version.to_i
      @always_add_header = always_add_header
      @key_filename      = key_filename
      @iv_filename       = iv_filename
      @key_env_var       = key_env_var

      @key_encryption_key =
        if key_encryption_key
          key_encryption_key
        elsif private_rsa_key
          KeyEncryptionKey.new(private_rsa_key)
        end

      raise(ArgumentError, "Cipher version has a valid range of 0 to 255. #{@version} is too high, or negative") if (@version > 255) || (@version < 0)

      if key_filename || encrypted_key || iv_filename || encrypted_iv
        raise(SymmetricEncryption::ConfigError, 'Missing required :private_rsa_key, or :key_encryption_key') unless @key_encryption_key
      end

      @key =
        if key != :random && key != nil
          key
        elsif key_filename
          Keystore::File.new(file_name: key_filename, key_encryption_key: @key_encryption_key).read
        elsif encrypted_key
          Keystore::Memory.new(encrypted_key: encrypted_key, key_encryption_key: @key_encryption_key).read
        elsif key_env_var
          Keystore::Environment.new(key_env_var: key_env_var, key_encryption_key: @key_encryption_key).read
        elsif key == :random
          random_key
        else
          raise(ArgumentError, 'Missing mandatory parameter :key, :key_filename, or :encrypted_key')
        end

      @iv =
        if iv != :random && iv != nil
          iv
        elsif iv_filename
          Keystore::File.new(file_name: iv_filename, key_encryption_key: @key_encryption_key).read
        elsif encrypted_iv
          Keystore::Memory.new(encrypted_key: encrypted_iv, key_encryption_key: @key_encryption_key).read
        elsif iv == :random
          random_iv
        end

    end

    # Returns [Hash] the configuration for this cipher.
    def to_h
      h = {
        cipher_name:       cipher_name,
        encoding:          encoding,
        version:           version,
        always_add_header: always_add_header
      }

      if key_filename
        h[:key_filename] = key_filename
      else
        h[:encrypted_key] = encoder.encode(encrypted_key)
      end

      if iv_filename
        h[:iv_filename] = iv_filename
      else
        h[:iv] = encoder.encode(iv)
      end

      h
    end

    # Returns the key encrypted with the key encryption key.
    def encrypted_key
      key_encryption_key.encrypt(key)
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
    #     Whether the encypted value should use a random IV every time the
    #     field is encrypted.
    #     It is recommended to set this to true where feasible. If the encrypted
    #     value could be used as part of a SQL where clause, or as part
    #     of any lookup, then it must be false.
    #     Setting random_iv to true will result in a different encrypted output for
    #     the same input string.
    #     Note: Only set to true if the field will never be used as part of
    #       the where clause in an SQL query.
    #     Note: When random_iv is true it will add a 8 byte header, plus the bytes
    #       to store the random IV in every returned encrypted string, prior to the
    #       encoding if any.
    #     Default: false
    #     Highly Recommended where feasible: true
    #
    #   compress [true|false]
    #     Whether to compress str before encryption
    #     Should only be used for large strings since compression overhead and
    #     the overhead of adding the encryption header may exceed any benefits of
    #     compression
    #     Note: Adds a 6 byte header prior to encoding, only if :random_iv is false
    #     Default: false
    def encrypt(str, random_iv: false, compress: false)
      return if str.nil?
      str = str.to_s
      return str if str.empty?
      encrypted = binary_encrypt(str, random_iv: random_iv, compress: compress)
      self.encode(encrypted)
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
      decoded = self.decode(str)
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
      return binary_string if binary_string.nil? || (binary_string == '')
      encoder.encode(binary_string)
    end

    # Decode the supplied string using the encoding in this cipher instance
    # Note: No encryption or decryption is performed
    #
    # Returned string is Binary encoded
    def decode(encoded_string)
      return encoded_string if encoded_string.nil? || (encoded_string == '')
      encoder.decode(encoded_string)
    end

    # Return a new random key using the configured cipher_name
    # Useful for generating new symmetric keys
    def random_key
      ::OpenSSL::Cipher::Cipher.new(cipher_name).random_key
    end

    # Return a new random IV using the configured cipher_name
    # Useful for generating new symmetric keys
    def random_iv
      ::OpenSSL::Cipher::Cipher.new(cipher_name).random_iv
    end

    # Returns the block size for the configured cipher_name
    def block_size
      ::OpenSSL::Cipher::Cipher.new(cipher_name).block_size
    end

    # Advanced use only
    #
    # Returns a Binary encrypted string without applying any Base64, or other encoding
    #
    #   add_header [true|false]
    #     Whether to add a header to the encrypted string.
    #     Default: `always_add_header`
    #
    # Use #encrypt to encrypt and encode the result as a string.
    def binary_encrypt(str, random_iv: false, compress: false, add_header: always_add_header)
      return if str.nil?
      string = str.to_s
      return string if string.empty?

      # Creates a new OpenSSL::Cipher with every call so that this call is thread-safe.
      openssl_cipher = ::OpenSSL::Cipher.new(cipher_name)
      openssl_cipher.encrypt
      openssl_cipher.key = @key

      # Header required when adding a random_iv or compressing
      add_header         = true if random_iv || compress

      result =
        if add_header
          iv                = random_iv ? openssl_cipher.random_iv : iv
          openssl_cipher.iv = iv if iv
          # Set the binary indicator on the header if string is Binary Encoded
          header = Header.new(version: version, compressed: compress, iv: random_iv ? iv : nil)
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
      str.force_encoding(SymmetricEncryption::BINARY_ENCODING) if str.respond_to?(:force_encoding)
      return str if str.empty?

      offset = header.parse(str)
      data   = offset > 0 ? str[offset..-1] : str

      openssl_cipher = ::OpenSSL::Cipher.new(header.cipher_name || cipher_name)
      openssl_cipher.decrypt
      openssl_cipher.key = header.key || @key
      if iv = (header.iv || @iv)
        openssl_cipher.iv = iv
      end
      result = openssl_cipher.update(data)
      result << openssl_cipher.final
      header.compressed ? Zlib::Inflate.inflate(result) : result
    end

    # Returns [String] object represented as a string, filtering out the key
    def inspect
      "#<#{self.class}:0x#{self.__id__.to_s(16)} @key=\"[FILTERED]\" @iv=#{iv.inspect} @cipher_name=#{cipher_name.inspect}, @version=#{version.inspect}, @encoding=#{encoding.inspect}, @always_add_header=#{always_add_header.inspect}, @key_filename=#{key_filename.inspect}, @iv_filename=#{iv_filename.inspect}, key_encryption_key=#{key_encryption_key.inspect}>"
    end

    # DEPRECATED
    def self.has_header?(buffer)
      SymmetricEncryption::Header.present?(buffer)
    end

    # DEPRECATED
    def self.parse_header!(buffer)
      header = SymmetricEncryption::Header.new
      header.parse!(buffer) == 0 ? nil : header
    end

    # DEPRECATED
    def self.build_header(version, compressed = false, iv = nil, key = nil, cipher_name = nil)
      Header.new(version: version, compressed: compressed, iv: iv, key: key, cipher_name: cipher_name).to_s
    end

    # DEPRECATED
    def self.random_key_pair(cipher_name = 'aes-256-cbc')
      openssl_cipher = ::OpenSSL::Cipher.new(cipher_name)
      openssl_cipher.encrypt

      {
        key:         openssl_cipher.random_key,
        iv:          openssl_cipher.random_iv,
        cipher_name: cipher_name
      }
    end

    # DEPRECATED
    def self.generate_random_keys(cipher_name: 'aes-256-cbc',
      encoding: :base64strict,
      private_rsa_key: nil,
      key_filename: nil, encrypted_key: nil,
      iv_filename: nil, encrypted_iv: nil)

      Cipher.new(
        cipher_name:     cipher_name,
        encoding:        encoding,
        private_rsa_key: private_rsa_key,
        key_filename:    key_filename,
        iv_filename:     iv_filename
      ).to_h
    end

    private

    attr_reader :key

  end
end
