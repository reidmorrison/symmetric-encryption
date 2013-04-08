module SymmetricEncryption

  # Hold all information related to encryption keys
  # as well as encrypt and decrypt data using those keys
  #
  # Cipher is thread safe so that the same instance can be called by multiple
  # threads at the same time without needing an instance of Cipher per thread
  class Cipher
    # Cipher to use for encryption and decryption
    attr_reader :cipher, :version
    attr_accessor :encoding

    # Available encodings
    ENCODINGS = [:none, :base64, :base64strict, :base16]

    # Generate a new Symmetric Key pair
    #
    # Returns a hash containing a new random symmetric_key pair
    # consisting of a :key and :iv.
    # The cipher is also included for compatibility with the Cipher initializer
    def self.random_key_pair(cipher = 'aes-256-cbc', generate_iv = true)
      openssl_cipher = OpenSSL::Cipher.new(cipher)
      openssl_cipher.encrypt

      {
        :key    => openssl_cipher.random_key,
        :iv     => generate_iv ? openssl_cipher.random_iv : nil,
        :cipher => cipher
      }
    end

    # Returns a new Cipher with a random key and iv
    #
    # The cipher and encoding used are from the global encryption cipher
    #
    def self.random_cipher(cipher=nil, encoding=nil)
      global_cipher = SymmetricEncryption.cipher
      options = random_key_pair(cipher || global_cipher.cipher)
      options[:encoding] = encoding || global_cipher.encoding
      new(options)
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
    #   :cipher [String]
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
      @cipher = parms[:cipher] || 'aes-256-cbc'
      @version = parms[:version]
      raise "Cipher version has a maximum of 255. #{@version} is too high" if @version.to_i > 255
      @encoding = (parms[:encoding] || :base64).to_sym

      raise("Invalid Encoding: #{@encoding}") unless ENCODINGS.include?(@encoding)
    end

    # Encryption of supplied string
    # The String is encoded to UTF-8 prior to encryption
    #
    #  Returns result as an encoded string if encode is true
    #  Returns nil if the supplied str is nil
    #  Returns "" if it is a string and it is empty
    if defined?(Encoding)
      def encrypt(str, encode = true)
        return if str.nil?
        str = str.to_s  #.force_encoding(SymmetricEncryption::BINARY_ENCODING)
        return str if str.empty?
        encrypted = crypt(:encrypt, str)
        encode ? self.encode(encrypted) : encrypted
      end
    else
      def encrypt(str, encode = true)
        return if str.nil?
        buf = str.to_s
        return str if buf.empty?
        encrypted = crypt(:encrypt, buf)
        encode ? self.encode(encrypted) : encrypted
      end
    end

    # Decryption of supplied string
    #
    # Decodes string first if decode is true
    #
    #  Returns a UTF-8 encoded, decrypted string
    #  Returns nil if the supplied str is nil
    #  Returns "" if it is a string and it is empty
    if defined?(Encoding)
      def decrypt(str, decode = true)
        decoded = self.decode(str) if decode
        return unless decoded

        return decoded if decoded.empty?
        crypt(:decrypt, decoded).force_encoding(SymmetricEncryption::UTF8_ENCODING)
      end

      # Returns a binary decrypted string
      def decrypt_binary(str, decode = true)
        decoded = self.decode(str) if decode
        return unless decoded

        return decoded if decoded.empty?
        crypt(:decrypt, decoded).force_encoding(SymmetricEncryption::BINARY_ENCODING)
      end
    else
      def decrypt(str, decode = true)
        decoded = self.decode(str) if decode
        return unless decoded

        return decoded if decoded.empty?
        crypt(:decrypt, decoded)
      end
    end

    # Return a new random key using the configured cipher
    # Useful for generating new symmetric keys
    def random_key
      ::OpenSSL::Cipher::Cipher.new(@cipher).random_key
    end

    # Returns the block size for the configured cipher
    def block_size
      ::OpenSSL::Cipher::Cipher.new(@cipher).block_size
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

    # Returns an Array with the first element being Symmetric Cipher that must
    # be used to decrypt the data. The second element indicates whether the data
    # must be decompressed after decryption
    #
    # If the buffer does not start with the Magic Header the global cipher will
    # be returned
    #
    # The supplied buffer will be updated directly and will have the header
    # portion removed
    def self.parse_magic_header!(buffer)
      buffer.force_encoding(SymmetricEncryption::BINARY_ENCODING)
      return [SymmetricEncryption.cipher, false] unless buffer.start_with?(MAGIC_HEADER)

      # Header includes magic header and version byte
      # Remove header and extract flags
      header, flags = buffer.slice!(0..MAGIC_HEADER_SIZE+1).unpack(MAGIC_HEADER_UNPACK)
      compressed    = (flags & 0b1000_0000_0000_0000) != 0
      include_iv    = (flags & 0b0100_0000_0000_0000) != 0
      include_key   = (flags & 0b0010_0000_0000_0000) != 0
      include_cipher= (flags & 0b0001_0000_0000_0000) != 0
      version       = flags & 0b0000_0000_1111_1111
      decryption_cipher = SymmetricEncryption.cipher(version)
      raise "Cipher with version:#{version.inspect} not found in any of the configured SymmetricEncryption ciphers" unless decryption_cipher
      iv, key, cipher   = nil

      if include_iv
        len = buffer.slice!(0..1).unpack('v').first
        iv  = decryption_cipher.send(:crypt, :decrypt, buffer.slice!(0..len-1))
      end
      if include_key
        len = buffer.slice!(0..1).unpack('v').first
        key = decryption_cipher.send(:crypt, :decrypt, buffer.slice!(0..len-1))
      end
      if include_cipher
        len    = buffer.slice!(0..1).unpack('v').first
        cipher = buffer.slice!(0..len-1)
      end

      if iv || key || cipher
        decryption_cipher = SymmetricEncryption::Cipher.new(
          :iv     => iv,
          :key    => key || decryption_cipher.key,
          :cipher => cipher || decryption_cipher.cipher
        )
      end

      [decryption_cipher, compressed]
    end

    # Returns a magic header for this cipher instance that can be placed at
    # the beginning of a file or stream to indicate how the data was encrypted
    #
    # Parameters
    #   compressed
    #     Sets the compressed indicator in the header
    #
    #   include_iv
    #     Includes the encrypted Initialization Vector from this cipher if present
    #     The IV is encrypted using the global encryption key
    #
    #   include_key
    #     Includes the encrypted Key in this cipher
    #     The key is encrypted using the global encryption key
    #
    #   include_cipher
    #     Includes the cipher used. For example 'aes-256-cbc'
    #
    #  encryption_cipher
    #    Encryption cipher to use when encrypting the iv and key.
    #    When supplied, the version is set to it's version so that decryption
    #    knows which cipher to use
    #    Default: Global cipher: SymmetricEncryption.cipher
    def magic_header(compressed=false, include_iv=false, include_key=false, include_cipher=false, encryption_cipher=nil)
      # Ruby V2 named parameters would be perfect here

      # Encryption version indicator if available
      flags  = version || 0 # Same as 0b0000_0000_0000_0000
      flags = encryption_cipher.version || 0 if (include_iv || include_key) && encryption_cipher

      # If the data is to be compressed before being encrypted, set the
      # compressed bit in the flags word
      flags |= 0b1000_0000_0000_0000 if compressed
      flags |= 0b0100_0000_0000_0000 if @iv && include_iv
      flags |= 0b0010_0000_0000_0000 if include_key
      flags |= 0b0001_0000_0000_0000 if include_cipher
      header = "#{MAGIC_HEADER}#{[flags].pack('v')}".force_encoding(SymmetricEncryption::BINARY_ENCODING)
      if @iv && include_iv
        encryption_cipher ||= SymmetricEncryption.cipher
        encrypted = encryption_cipher.crypt(:encrypt, @iv).force_encoding(SymmetricEncryption::BINARY_ENCODING)
        header << [encrypted.length].pack('v').force_encoding(SymmetricEncryption::BINARY_ENCODING)
        header << encrypted
      end
      if include_key
        encryption_cipher ||= SymmetricEncryption.cipher
        encrypted = encryption_cipher.crypt(:encrypt, @key).force_encoding(SymmetricEncryption::BINARY_ENCODING)
        header << [encrypted.length].pack('v').force_encoding(SymmetricEncryption::BINARY_ENCODING)
        header << encrypted
      end
      if include_cipher
        header << [cipher.length].pack('v')
        header << cipher
      end
      header
    end

    protected

    # Only for use by Symmetric::EncryptedStream
    def openssl_cipher(cipher_method)
      openssl_cipher = ::OpenSSL::Cipher.new(self.cipher)
      openssl_cipher.send(cipher_method)
      openssl_cipher.key = @key
      openssl_cipher.iv = @iv if @iv
      openssl_cipher
    end

    # Creates a new OpenSSL::Cipher with every call so that this call
    # is thread-safe
    # Return a binary encoded decrypted or encrypted string
    def crypt(cipher_method, string) #:nodoc:
      openssl_cipher = ::OpenSSL::Cipher.new(self.cipher)
      openssl_cipher.send(cipher_method)
      openssl_cipher.key = @key
      openssl_cipher.iv = @iv if @iv
      result = openssl_cipher.update(string)
      result << openssl_cipher.final
      result.force_encoding(SymmetricEncryption::BINARY_ENCODING)
    end

    private

    attr_reader :key, :iv

  end
end