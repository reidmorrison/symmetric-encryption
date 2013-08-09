module SymmetricEncryption

  # Hold all information related to encryption keys
  # as well as encrypt and decrypt data using those keys
  #
  # Cipher is thread safe so that the same instance can be called by multiple
  # threads at the same time without needing an instance of Cipher per thread
  class Cipher
    # Cipher to use for encryption and decryption
    attr_reader :cipher_name, :version
    attr_accessor :encoding, :always_add_header

    # Available encodings
    ENCODINGS = [:none, :base64, :base64strict, :base16]

    # Backward compatibility
    alias_method :cipher, :cipher_name

    # Defines the Header Structure returned when parsing the header
    HeaderStruct = Struct.new(
      :compressed,          # [true|false] Whether the data is compressed, if supplied in the header
      :binary,              # [true|false] Whether the data is binary, if supplied in the header
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

    # Returns encrypted binary string
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
      string = str.to_s
      return string if string.empty?

      # Creates a new OpenSSL::Cipher with every call so that this call
      # is thread-safe
      openssl_cipher = ::OpenSSL::Cipher.new(self.cipher_name)
      openssl_cipher.encrypt
      openssl_cipher.key = @key
      result = if always_add_header || random_iv || compress
        # Random iv and compress both add the magic header
        iv = random_iv ? openssl_cipher.random_iv : @iv
        openssl_cipher.iv = iv if iv
        # Set the binary indicator on the header if string is Binary Encoded
        binary = (string.encoding == SymmetricEncryption::BINARY_ENCODING)
        self.class.build_header(version, compress, random_iv ? iv : nil, binary) +
          openssl_cipher.update(compress ? Zlib::Deflate.deflate(string) : string)
      else
        openssl_cipher.iv = @iv if @iv
        openssl_cipher.update(string)
      end
      result << openssl_cipher.final
    end

    # Decryption of supplied string
    #   Returns a UTF-8 binary, decrypted string
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
    #   binary [true|false]
    #     If no header is supplied then determines whether the string returned
    #     is binary or UTF8
    #
    # Reads the 'magic' header if present for key, iv, cipher_name and compression
    #
    # encrypted_string must be in raw binary form when calling this method
    #
    # Creates a new OpenSSL::Cipher with every call so that this call
    # is thread-safe and can be called concurrently by multiple threads with
    # the same instance of Cipher
    def decrypt(encrypted_string, header=nil, binary=false)
      return if encrypted_string.nil?
      str = encrypted_string.to_s
      str.force_encoding(SymmetricEncryption::BINARY_ENCODING) if str.respond_to?(:force_encoding)
      return str if str.empty?

      decrypted_string = if header || self.class.has_header?(str)
        str = str.dup
        header ||= self.class.parse_header!(str)
        binary = header.binary

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

      # Support Ruby 1.9 and above Encoding
      if defined?(Encoding)
        # Sets the encoding of the result string to UTF8 or BINARY based on the binary header
        binary ? decrypted_string.force_encoding(SymmetricEncryption::BINARY_ENCODING) : decrypted_string.force_encoding(SymmetricEncryption::UTF8_ENCODING)
      else
        decrypted_string
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
      # Remove header and extract flags
      _, flags      = buffer.slice!(0..MAGIC_HEADER_SIZE+1).unpack(MAGIC_HEADER_UNPACK)
      compressed    = (flags & 0b1000_0000_0000_0000) != 0
      include_iv    = (flags & 0b0100_0000_0000_0000) != 0
      include_key   = (flags & 0b0010_0000_0000_0000) != 0
      include_cipher= (flags & 0b0001_0000_0000_0000) != 0
      binary        = (flags & 0b0000_1000_0000_0000) != 0
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
        key = decryption_cipher.decrypt(buffer.slice!(0..len-1), header=false, binary=true)
      end
      if include_cipher
        len    = buffer.slice!(0..1).unpack('v').first
        cipher_name = buffer.slice!(0..len-1)
      end

      HeaderStruct.new(compressed, binary, iv, key, cipher_name, version, decryption_cipher)
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
    def self.build_header(version, compressed=false, iv=nil, key=nil, cipher_name=nil, binary=false)
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
      flags |= 0b0000_1000_0000_0000 if binary
      header = "#{MAGIC_HEADER}#{[flags].pack('v')}".force_encoding(SymmetricEncryption::BINARY_ENCODING)
      if iv
        header << [iv.length].pack('v')
        header << iv
      end
      if key
        encrypted = SymmetricEncryption.cipher.encrypt(key, false, false)
        header << [encrypted.length].pack('v').force_encoding(SymmetricEncryption::BINARY_ENCODING)
        header << encrypted
      end
      if cipher_name
        header << [cipher_name.length].pack('v')
        header << cipher_name
      end
      header
    end

    # Returns [String] object represented as a string, filtering out the key
    def inspect
      "#<#{self.class}:0x#{self.__id__.to_s(16)} @key=\"[FILTERED]\" @iv=#{iv.inspect} @cipher_name=#{cipher_name.inspect}, @version=#{version.inspect}, @encoding=#{encoding.inspect}"
    end

    private

    attr_reader :key, :iv
  end
end