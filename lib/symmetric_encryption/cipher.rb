module SymmetricEncryption

  # Hold all information related to encryption keys
  # as well as encrypt and decrypt data using those keys
  #
  # Cipher is thread safe so that the same instance can be called by multiple
  # threads at the same time without needing an instance of Cipher per thread
  class Cipher
    # Cipher to use for encryption and decryption
    attr_reader :cipher_name, :version, :iv
    attr_accessor :encoding, :always_add_header

    # Available encodings
    ENCODINGS = [:none, :base64, :base64strict, :base16]

    # Backward compatibility
    alias_method :cipher, :cipher_name

    # Defines the Header Structure returned when parsing the header
    HeaderStruct = Struct.new(
      :compressed,          # [true|false] Whether the data is compressed, if supplied in the header
      :iv,                  # [String] IV used to encrypt the data, if supplied in the header
      :key,                 # [String] Key used to encrypt the data, if supplied in the header
      :cipher_name,         # [String] Name of the cipher used, if supplied in the header
      :version,             # [Integer] Version of the cipher used, if supplied in the header
      :decryption_cipher,   # [SymmetricEncryption::Cipher] Cipher matching the header, or SymmetricEncryption.cipher(default_version)
    )

    # Generate a new Symmetric Key pair
    #
    # Returns a hash containing a new random symmetric_key pair
    # consisting of a :key and :iv.
    # The cipher_name is also included for compatibility with the Cipher initializer
    def self.random_key_pair(cipher_name = 'aes-256-cbc')
      openssl_cipher = ::OpenSSL::Cipher.new(cipher_name)
      openssl_cipher.encrypt

      {
        :key         => openssl_cipher.random_key,
        :iv          => openssl_cipher.random_iv,
        :cipher_name => cipher_name
      }
    end

    # Create a Symmetric::Key for encryption and decryption purposes
    #
    # Parameters:
    #   :key [String]
    #     The Symmetric Key to use for encryption and decryption
    #
    #   :iv [String]
    #     Optional. The Initialization Vector to use with Symmetric Key
    #     Highly Recommended as it is the input into the CBC algorithm
    #
    #   :cipher_name [String]
    #     Optional. Encryption Cipher to use
    #     Default: aes-256-cbc
    #
    #   :encoding [Symbol]
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
    #     Default: :base64
    #     Recommended: :base64strict
    #
    #   :version [Fixnum]
    #     Optional. The version number of this encryption key
    #     Used by SymmetricEncryption to select the correct key when decrypting data
    #     Maximum value: 255
    #
    #   :always_add_header [true|false]
    #     Whether to always include the header when encrypting data.
    #     ** Highly recommended to set this value to true **
    #     Increases the length of the encrypted data by a few bytes, but makes
    #     migration to a new key trivial
    #     Default: false
    #     Recommended: true
    #
    def initialize(params={})
      parms              = params.dup
      @key               = parms.delete(:key)
      @iv                = parms.delete(:iv)
      @cipher_name       = parms.delete(:cipher_name) || parms.delete(:cipher) || 'aes-256-cbc'
      @version           = parms.delete(:version)
      @always_add_header = parms.delete(:always_add_header) || false
      @encoding          = (parms.delete(:encoding) || :base64).to_sym

      raise "Missing mandatory parameter :key" unless @key
      raise "Invalid Encoding: #{@encoding}" unless ENCODINGS.include?(@encoding)
      raise "Cipher version has a valid rage of 0 to 255. #{@version} is too high, or negative" if (@version.to_i > 255) || (@version.to_i < 0)
      parms.each_pair {|k,v| warn "SymmetricEncryption::Cipher Ignoring unknown option #{k.inspect} = #{v.inspect}"}
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
    def encrypt(str, random_iv=false, compress=false)
      return if str.nil?
      str = str.to_s
      return str if str.empty?
      encrypted = binary_encrypt(str, random_iv, compress)
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
      if defined?(Encoding)
        # Try to force result to UTF-8 encoding, but if it is not valid, force it back to Binary
        unless decrypted.force_encoding(SymmetricEncryption::UTF8_ENCODING).valid_encoding?
          decrypted.force_encoding(SymmetricEncryption::BINARY_ENCODING)
        end
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

      # Now encode data based on encoding setting
      case encoding
      when :base64
        encoded_string = ::Base64.encode64(binary_string)
        # Support Ruby 1.9 encoding
        defined?(Encoding) ? encoded_string.force_encoding(SymmetricEncryption::UTF8_ENCODING) : encoded_string
      when :base64strict
        encoded_string = ::Base64.encode64(binary_string).gsub(/\n/, '')
        # Support Ruby 1.9 encoding
        defined?(Encoding) ? encoded_string.force_encoding(SymmetricEncryption::UTF8_ENCODING) : encoded_string
      when :base16
        encoded_string = binary_string.to_s.unpack('H*').first
        # Support Ruby 1.9 encoding
        defined?(Encoding) ? encoded_string.force_encoding(SymmetricEncryption::UTF8_ENCODING) : encoded_string
      else
        binary_string
      end
    end

    # Decode the supplied string using the encoding in this cipher instance
    # Note: No encryption or decryption is performed
    #
    # Returned string is Binary encoded
    def decode(encoded_string)
      return encoded_string if encoded_string.nil? || (encoded_string == '')

      case encoding
      when :base64, :base64strict
        decoded_string = ::Base64.decode64(encoded_string)
        # Support Ruby 1.9 encoding
        defined?(Encoding) ? decoded_string.force_encoding(SymmetricEncryption::BINARY_ENCODING) : decoded_string
      when :base16
        decoded_string = [encoded_string].pack('H*')
        # Support Ruby 1.9 encoding
        defined?(Encoding) ? decoded_string.force_encoding(SymmetricEncryption::BINARY_ENCODING) : decoded_string
      else
        encoded_string
      end
    end

    # Return a new random key using the configured cipher_name
    # Useful for generating new symmetric keys
    def random_key
      ::OpenSSL::Cipher::Cipher.new(@cipher_name).random_key
    end

    # Returns the block size for the configured cipher_name
    def block_size
      ::OpenSSL::Cipher::Cipher.new(@cipher_name).block_size
    end

    # Returns whether the supplied buffer starts with a symmetric_encryption header
    # Note: The encoding of the supplied buffer is forced to binary if not already binary
    def self.has_header?(buffer)
      return false if buffer.nil? || (buffer == '')
      buffer.force_encoding(SymmetricEncryption::BINARY_ENCODING) if buffer.respond_to?(:force_encoding)
      buffer.start_with?(MAGIC_HEADER)
    end

    # Returns HeaderStruct of the header parsed from the supplied string
    # Returns nil if no header is present
    #
    # The supplied buffer will be updated directly and its header will be
    # stripped if present
    #
    # Parameters
    #   buffer
    #     String to extract the header from
    #
    def self.parse_header!(buffer)
      return unless has_header?(buffer)

      # Header includes magic header and version byte
      #
      # The encryption header consists of:
      #    4 Byte Magic Header Prefix: @Enc
      #    Followed by 2 Bytes (16 bits)
      #       Bit 0 through 7: The version of the cipher used to encrypt the header
      #       Bit 8 though 10: Reserved
      #       Bit 11: Whether the encrypted data is Binary (otherwise UTF8 text)
      #       Bit 12: Whether the Cipher Name is included
      #       Bit 13: Whether the Key is included
      #       Bit 14: Whether the IV is included
      #       Bit 15: Whether the data is compressed
      #    2 Byte IV Length if included
      #    IV in binary form
      #    2 Byte Key Length if included
      #    Key in binary form
      #    2 Byte Cipher Name Length if included
      #    Cipher name it UTF8 text

      # Remove header and extract flags
      _, flags      = buffer.slice!(0..MAGIC_HEADER_SIZE+1).unpack(MAGIC_HEADER_UNPACK)
      compressed    = (flags & 0b1000_0000_0000_0000) != 0
      include_iv    = (flags & 0b0100_0000_0000_0000) != 0
      include_key   = (flags & 0b0010_0000_0000_0000) != 0
      include_cipher= (flags & 0b0001_0000_0000_0000) != 0
      # Version of the key to use to decrypt the key if present,
      # otherwise to decrypt the data following the header
      version       = flags & 0b0000_0000_1111_1111
      decryption_cipher = SymmetricEncryption.cipher(version)
      raise "Cipher with version:#{version.inspect} not found in any of the configured SymmetricEncryption ciphers" unless decryption_cipher
      iv, key, cipher_name   = nil

      if include_iv
        len = buffer.slice!(0..1).unpack('v').first
        iv  = buffer.slice!(0..len-1)
      end
      if include_key
        len = buffer.slice!(0..1).unpack('v').first
        key = decryption_cipher.binary_decrypt(buffer.slice!(0..len-1), header=false)
      end
      if include_cipher
        len    = buffer.slice!(0..1).unpack('v').first
        cipher_name = buffer.slice!(0..len-1)
      end

      HeaderStruct.new(compressed, iv, key, cipher_name, version, decryption_cipher)
    end

    # Returns a magic header for this cipher instance that can be placed at
    # the beginning of a file or stream to indicate how the data was encrypted
    #
    # Parameters
    #   compressed
    #     Sets the compressed indicator in the header
    #     Default: false
    #
    #   iv
    #     The iv to to put in the header
    #     Default: nil : Exclude from header
    #
    #   key
    #     The key to to put in the header
    #     The key is encrypted using the global encryption key
    #     Default: nil : Exclude key from header
    #
    #   cipher_name
    #     Includes the cipher_name used. For example 'aes-256-cbc'
    #     The cipher_name string to to put in the header
    #     Default: nil : Exclude cipher_name name from header
    def self.build_header(version, compressed=false, iv=nil, key=nil, cipher_name=nil)
      # Ruby V2 named parameters would be perfect here

      # Version number of supplied encryption key, or use the global cipher version if none was supplied
      flags = iv || key ? (SymmetricEncryption.cipher.version || 0) : (version || 0) # Same as 0b0000_0000_0000_0000

      # If the data is to be compressed before being encrypted, set the
      # compressed bit in the flags word
      flags |= 0b1000_0000_0000_0000 if compressed
      flags |= 0b0100_0000_0000_0000 if iv
      flags |= 0b0010_0000_0000_0000 if key
      flags |= 0b0001_0000_0000_0000 if cipher_name
      header = "#{MAGIC_HEADER}#{[flags].pack('v')}".force_encoding(SymmetricEncryption::BINARY_ENCODING)
      if iv
        header << [iv.length].pack('v')
        header << iv
      end
      if key
        encrypted = SymmetricEncryption.cipher.binary_encrypt(key, false, false, false)
        header << [encrypted.length].pack('v').force_encoding(SymmetricEncryption::BINARY_ENCODING)
        header << encrypted
      end
      if cipher_name
        header << [cipher_name.length].pack('v')
        header << cipher_name
      end
      header
    end

    # Advanced use only
    #
    # Returns a Binary encrypted string without applying any Base64, or other encoding
    #
    #   add_header [nil|true|false]
    #     Whether to add a header to the encrypted string
    #     If not supplied it defaults to true if always_add_header || random_iv || compress
    #     Default: nil
    #
    # Creates a new OpenSSL::Cipher with every call so that this call
    # is thread-safe
    #
    # See #encrypt to encrypt and encode the result as a string
    def binary_encrypt(str, random_iv=false, compress=false, add_header=nil)
      return if str.nil?
      string = str.to_s
      return string if string.empty?

      # Creates a new OpenSSL::Cipher with every call so that this call
      # is thread-safe
      openssl_cipher = ::OpenSSL::Cipher.new(self.cipher_name)
      openssl_cipher.encrypt
      openssl_cipher.key = @key
      add_header = always_add_header || random_iv || compress if add_header.nil?
      result = if add_header
        # Random iv and compress both add the magic header
        iv = random_iv ? openssl_cipher.random_iv : @iv
        openssl_cipher.iv = iv if iv
        # Set the binary indicator on the header if string is Binary Encoded
        self.class.build_header(version, compress, random_iv ? iv : nil, nil, nil) +
          openssl_cipher.update(compress ? Zlib::Deflate.deflate(string) : string)
      else
        openssl_cipher.iv = @iv if @iv
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
    #   header [HeaderStruct]
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
    def binary_decrypt(encrypted_string, header=nil)
      return if encrypted_string.nil?
      str = encrypted_string.to_s
      str.force_encoding(SymmetricEncryption::BINARY_ENCODING) if str.respond_to?(:force_encoding)
      return str if str.empty?

      if header || self.class.has_header?(str)
        str = str.dup
        header ||= self.class.parse_header!(str)

        openssl_cipher = ::OpenSSL::Cipher.new(header.cipher_name || self.cipher_name)
        openssl_cipher.decrypt
        openssl_cipher.key = header.key || @key
        iv = header.iv || @iv
        openssl_cipher.iv = iv if iv
        result = openssl_cipher.update(str)
        result << openssl_cipher.final
        header.compressed ? Zlib::Inflate.inflate(result) : result
      else
        openssl_cipher = ::OpenSSL::Cipher.new(self.cipher_name)
        openssl_cipher.decrypt
        openssl_cipher.key = @key
        openssl_cipher.iv = @iv if @iv
        result = openssl_cipher.update(str)
        result << openssl_cipher.final
      end
    end

    # Returns [String] object represented as a string, filtering out the key
    def inspect
      "#<#{self.class}:0x#{self.__id__.to_s(16)} @key=\"[FILTERED]\" @iv=#{iv.inspect} @cipher_name=#{cipher_name.inspect}, @version=#{version.inspect}, @encoding=#{encoding.inspect}, @always_add_header=#{always_add_header.inspect}"
    end

    private

    attr_reader :key
  end
end
