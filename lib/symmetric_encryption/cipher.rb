module SymmetricEncryption

  # Hold all information related to encryption keys
  # as well as encrypt and decrypt data using those keys
  #
  # Cipher is thread safe so that the same instance can be called by multiple
  # threads at the same time without needing an instance of Cipher per thread
  class Cipher
    # Cipher to use for encryption and decryption
    attr_reader :cipher_name, :version
    attr_accessor :encoding

    # Available encodings
    ENCODINGS = [:none, :base64, :base64strict, :base16]

    # Backward compatibility
    alias_method :cipher, :cipher_name

    # Generate a new Symmetric Key pair
    #
    # Returns a hash containing a new random symmetric_key pair
    # consisting of a :key and :iv.
    # The cipher_name is also included for compatibility with the Cipher initializer
    def self.random_key_pair(cipher_name = 'aes-256-cbc', generate_iv = true)
      openssl_cipher = ::OpenSSL::Cipher.new(cipher_name)
      openssl_cipher.encrypt

      {
        :key         => openssl_cipher.random_key,
        :iv          => generate_iv ? openssl_cipher.random_iv : nil,
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
    def initialize(parms={})
      raise "Missing mandatory parameter :key" unless @key = parms[:key]
      @iv = parms[:iv]
      @cipher_name = parms[:cipher_name] || parms[:cipher] || 'aes-256-cbc'
      @version = parms[:version]
      raise "Cipher version has a maximum of 255. #{@version} is too high" if @version.to_i > 255
      @encoding = (parms[:encoding] || :base64).to_sym

      raise("Invalid Encoding: #{@encoding}") unless ENCODINGS.include?(@encoding)
    end

    # Returns encrypted and then encoded string
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
    #     the overhead of adding the 'magic' header may exceed any benefits of
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

    # Decryption of supplied string
    #
    # Decodes string first if decode is true
    #
    #  Returns a UTF-8 encoded, decrypted string
    #  Returns nil if the supplied str is nil
    #  Returns "" if it is a string and it is empty
    if defined?(Encoding)
      def decrypt(str)
        decoded = self.decode(str)
        return unless decoded

        return decoded if decoded.empty?
        binary_decrypt(decoded).force_encoding(SymmetricEncryption::UTF8_ENCODING)
      end
    else
      def decrypt(str)
        decoded = self.decode(str)
        return unless decoded

        return decoded if decoded.empty?
        crypt(:decrypt, decoded)
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

    # Returns UTF8 encoded string after encoding the supplied Binary string
    #
    # Encode the supplied string using the encoding in this cipher instance
    # Returns nil if the supplied string is nil
    # Note: No encryption or decryption is performed
    #
    # Returned string is UTF8 encoded except for encoding :none
    def encode(binary_string)
      return unless binary_string

      # Now encode data based on encoding setting
      case encoding
      when :base64
        ::Base64.encode64(binary_string).force_encoding(SymmetricEncryption::UTF8_ENCODING)
      when :base64strict
        ::Base64.encode64(binary_string).gsub(/\n/, '').force_encoding(SymmetricEncryption::UTF8_ENCODING)
      when :base16
        binary_string.to_s.unpack('H*').first.force_encoding(SymmetricEncryption::UTF8_ENCODING)
      else
        binary_string
      end
    end

    # Decode the supplied string using the encoding in this cipher instance
    # Note: No encryption or decryption is performed
    #
    # Returned string is Binary encoded
    def decode(encoded_string)
      return unless encoded_string

      case encoding
      when :base64, :base64strict
        ::Base64.decode64(encoded_string).force_encoding(SymmetricEncryption::BINARY_ENCODING)
      when :base16
        [encoded_string].pack('H*').force_encoding(SymmetricEncryption::BINARY_ENCODING)
      else
        encoded_string
      end
    end

    # Returns an Array of the following values extracted from header or nil
    # if any value was not specified in the header
    #   compressed [true|false]
    #   iv [String]
    #   key [String]
    #   cipher_name [String}
    #   decryption_cipher [SymmetricEncryption::Cipher]
    #
    # The supplied buffer will be updated directly and will have the header
    # portion removed
    #
    # Parameters
    #   buffer
    #     String to extract the header from if present
    #
    #   default_version
    #     If no header is present, this is the default value for the version
    #     of the cipher to use
    #
    #   default_compressed
    #     If no header is present, this is the default value for the compression
    def self.parse_magic_header!(buffer, default_version=nil, default_compressed=false)
      buffer.force_encoding(SymmetricEncryption::BINARY_ENCODING) if buffer
      return [default_compressed, nil, nil, nil, SymmetricEncryption.cipher(default_version)] unless buffer && buffer.start_with?(MAGIC_HEADER)

      # Header includes magic header and version byte
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
        key = decryption_cipher.binary_decrypt(buffer.slice!(0..len-1))
      end
      if include_cipher
        len    = buffer.slice!(0..1).unpack('v').first
        cipher_name = buffer.slice!(0..len-1)
      end

      [compressed, iv, key, cipher_name, decryption_cipher]
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
    def self.magic_header(version, compressed=false, iv=nil, key=nil, cipher_name=nil)
      # Ruby V2 named parameters would be perfect here

      # Encryption version indicator if available
      flags = version || 0 # Same as 0b0000_0000_0000_0000

      # Replace version with global cipher that will be used to encrypt the random key
      if iv || key
        flags = (SymmetricEncryption.cipher.version || 0)
      end

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
        encrypted = SymmetricEncryption.cipher.binary_encrypt(key, false, false)
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
    #   Adds the 'magic' header if a random_iv is required or compression is enabled
    #
    # Creates a new OpenSSL::Cipher with every call so that this call
    # is thread-safe
    #
    # See #encrypt to encrypt and encode the result as a string
    def binary_encrypt(string, random_iv=false, compress=false)
      openssl_cipher = ::OpenSSL::Cipher.new(self.cipher_name)
      openssl_cipher.encrypt
      openssl_cipher.key = @key
      result = if random_iv || compress
        # Random iv and compress both add the magic header
        iv = random_iv ? openssl_cipher.random_iv : @iv
        openssl_cipher.iv = iv if iv
        self.class.magic_header(version, compress, random_iv ? iv : nil) +
          openssl_cipher.update(compress ? Zlib::Deflate.deflate(string) : string)
      else
        openssl_cipher.iv = @iv if @iv
        openssl_cipher.update(string)
      end
      result << openssl_cipher.final
    end

    # Advanced use only
    #
    # Returns a Binary decrypted string without decoding the string first
    #
    # Reads the 'magic' header if present for key, iv, cipher_name and compression
    #
    # encrypted_string must be in raw binary form when calling this method
    #
    # Creates a new OpenSSL::Cipher with every call so that this call
    # is thread-safe
    #
    # See #decrypt to decrypt encoded strings
    def binary_decrypt(encrypted_string)
      str = encrypted_string.to_s
      if str.start_with?(MAGIC_HEADER)
        str = str.dup
        compressed, iv, key, cipher_name = self.class.parse_magic_header!(str)
        openssl_cipher = ::OpenSSL::Cipher.new(cipher_name || self.cipher_name)
        openssl_cipher.decrypt
        openssl_cipher.key = key || @key
        iv ||= @iv
        openssl_cipher.iv = iv if iv
        result = openssl_cipher.update(str)
        result << openssl_cipher.final
        compressed ? Zlib::Inflate.inflate(result) : result
      else
        openssl_cipher = ::OpenSSL::Cipher.new(self.cipher_name)
        openssl_cipher.decrypt
        openssl_cipher.key = @key
        openssl_cipher.iv = @iv if @iv
        result = openssl_cipher.update(encrypted_string)
        result << openssl_cipher.final
      end
    end

    # Returns [String] object represented as a string
    # Excluding the key and iv
    def inspect
       "#<#{self.class}:0x#{self.__id__.to_s(16)} @cipher_name=#{cipher_name.inspect}, @version=#{version.inspect}, @encoding=#{encoding.inspect}"
    end

    private

    attr_reader :key, :iv
  end
end