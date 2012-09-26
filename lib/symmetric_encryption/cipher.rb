module SymmetricEncryption

  # Hold all information related to encryption keys
  # as well as encrypt and decrypt data using those keys
  #
  # Cipher is thread safe so that the same instance can be called by multiple
  # threads at the same time without needing an instance of Cipher per thread
  class Cipher
    # Cipher to use for encryption and decryption
    attr_reader :cipher, :version, :version
    attr_accessor :encoding

    # Available encodings
    ENCODINGS = [:none, :base64, :base64strict]

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
    #     :binary
    #       Return as raw binary data string. Note: String can contain embedded nulls
    #     Default: :base64
    #     Recommended: :base64strict
    #
    #   :version [Fixnum]
    #     Optional. The version number of this encryption key
    #     Used by SymmetricEncryption to select the correct key when decrypting data
    def initialize(parms={})
      raise "Missing mandatory parameter :key" unless @key = parms[:key]
      @iv = parms[:iv]
      @cipher = parms[:cipher] || 'aes-256-cbc'
      @version = parms[:version]
      @encoding = (parms[:encoding] || :base64).to_sym

      raise("Invalid Encoding: #{@encoding}") unless ENCODINGS.include?(@encoding)
    end

    # AES Symmetric Encryption of supplied string
    # The String is encoded to UTF-8 prior to encryption
    #
    #  Returns result as a Base64 encoded string
    #  Returns nil if the supplied str is nil
    #  Returns "" if it is a string and it is empty
    if defined?(Encoding)
      def encrypt(str)
        return if str.nil?
        buf = str.to_s.encode(SymmetricEncryption::UTF8_ENCODING)
        return str if buf.empty?
        crypt(:encrypt, buf)
      end
    else
      def encrypt(str)
        return if str.nil?
        buf = str.to_s
        return str if buf.empty?
        crypt(:encrypt, buf)
      end
    end

    # AES Symmetric Decryption of supplied string
    # The encoding of the supplied string is ignored since it must be binary data
    #  Returns a UTF-8 encoded, decrypted string
    #  Returns nil if the supplied str is nil
    #  Returns "" if it is a string and it is empty
    if defined?(Encoding)
      def decrypt(str)
        return if str.nil?
        buf = str.to_s.force_encoding(SymmetricEncryption::BINARY_ENCODING)
        return str if buf.empty?
        crypt(:decrypt, buf).force_encoding(SymmetricEncryption::UTF8_ENCODING)
      end
    else
      def decrypt(str)
        return if str.nil?
        buf = str.to_s
        return str if buf.empty?
        crypt(:decrypt, buf)
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
    end

  end

end