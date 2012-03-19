require 'base64'
require 'openssl'
require 'zlib'

module Symmetric

  # Hold all information related to encryption keys
  # as well as encrypt and decrypt data using those keys
  #
  # Cipher is thread safe so that the same instance can be called by multiple
  # threads at the same time without needing an instance of Cipher per thread
  class Cipher
    # Cipher to use for encryption and decryption
    attr_reader :cipher

    # Future Use:
    # attr_accessor :encoding, :version

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
    #   :key
    #     The Symmetric Key to use for encryption and decryption
    #   :iv
    #     Optional. The Initialization Vector to use with Symmetric Key
    #   :cipher
    #     Optional. Encryption Cipher to use
    #     Default: aes-256-cbc
    def initialize(parms={})
      raise "Missing mandatory parameter :key" unless @key = parms[:key]
      @iv = parms[:iv]
      @cipher = parms[:cipher] || 'aes-256-cbc'
    end

    # AES Symmetric Encryption of supplied string
    #  Returns result as a Base64 encoded string
    #  Returns nil if the supplied str is nil
    #  Returns "" if it is a string and it is empty
    def encrypt(str)
      return str if str.nil? || (str.is_a?(String) && str.empty?)
      ::Base64.encode64(crypt(:encrypt, str))
    end

    # AES Symmetric Decryption of supplied string
    #  Returns decrypted string
    #  Returns nil if the supplied str is nil
    #  Returns "" if it is a string and it is empty
    def decrypt(str)
      return str if str.nil? || (str.is_a?(String) && str.empty?)
      crypt(:decrypt, ::Base64.decode64(str))
    end

    # The minimum length for an encrypted string
    def min_encrypted_length
      @min_encrypted_length ||= encrypt('1').length
    end

    # Returns [true|false] a best effort determination as to whether the supplied
    # string is encrypted or not, without incurring the penalty of actually
    # decrypting the supplied data
    #   Parameters:
    #     encrypted_data: Encrypted string
    def encrypted?(encrypted_data)
      # Simple checks first
      return false if (encrypted_data.length < min_encrypted_length) || (!encrypted_data.end_with?("\n"))
      # For now have to decrypt it fully
      begin
        decrypt(encrypted_data) ? true : false
      rescue
        false
      end
    end

    # Return a new random key using the configured cipher
    # Useful for generating new symmetric keys
    def random_key
      ::OpenSSL::Cipher::Cipher.new(@cipher).random_key
    end

    protected

    # Some of these methods are for future use to handle binary data, etc..

    # Binary encrypted data includes this magic header so that we can quickly
    # identify binary data versus base64 encoded data that does not have this header
    unless defined? MAGIC_HEADER
      MAGIC_HEADER = '@EnC'
      MAGIC_HEADER_SIZE = MAGIC_HEADER.size
    end

    # AES Symmetric Encryption of supplied string
    #  Returns result as a binary encrypted string
    #  Returns nil if the supplied str is nil or empty
    # Parameters
    #  compress => Whether to compress the supplied string using zip before
    #              encrypting
    #              true | false
    #              Default false
    def self.encrypt_binary(str, compress=false)
      return nil if str.nil? || (str.is_a?(String) && str.empty?)
      # Bit Layout
      # 15    => Compressed?
      # 0..14 => Version number of encryption key/algorithm currently 0
      flags = 0 # Same as 0b0000_0000_0000_0000
      # If the data is to be compressed before being encrypted, set the flag and
      # compress using zlib. Only compress if data is greater than 15 chars
      str = str.to_s unless str.is_a?(String)
      if compress && str.length > 15
        flags |= 0b1000_0000_0000_0000
        begin
          ostream = StringIO.new
          gz = ::Zlib::GzipWriter.new(ostream)
          gz.write(str)
          str = ostream.string
        ensure
          gz.close
        end
      end
      return nil unless encrypted = self.crypt(:encrypt, str)
      # Resulting buffer consists of:
      #   '@EnC'
      #   unsigned short (32 bits) in little endian format for flags above
      #   'actual encrypted buffer data'
      "#{MAGIC_HEADER}#{[flags].pack('v')}#{encrypted}"
    end

    # AES Symmetric Decryption of supplied Binary string
    #  Returns decrypted string
    #  Returns nil if the supplied str is nil
    #  Returns "" if it is a string and it is empty
    def self.decrypt_binary(str)
      return str if str.nil? || (str.is_a?(String) && str.empty?)
      str = str.to_s unless str.is_a?(String)
      encrypted = if str.starts_with? MAGIC_HEADER
        # Remove header and extract flags
        header, flags = str.unpack(@@unpack ||= "A#{MAGIC_HEADER_SIZE}v")
        # Uncompress if data is compressed and remove header
        if flags & 0b1000_0000_0000_0000
          begin
            gz = ::Zlib::GzipReader.new(StringIO.new(str[MAGIC_HEADER_SIZE,-1]))
            gz.read
          ensure
            gz.close
          end
        else
          str[MAGIC_HEADER_SIZE,-1]
        end
      else
        ::Base64.decode64(str)
      end
      crypt(:decrypt, encrypted)
    end

    # Creates a new OpenSSL::Cipher with every call so that this call
    # is thread-safe
    def crypt(cipher_method, string) #:nodoc:
      openssl_cipher = ::OpenSSL::Cipher.new(self.cipher)
      openssl_cipher.send(cipher_method)
      raise "Encryption.key must be set before calling Encryption encrypt or decrypt" unless @key
      openssl_cipher.key = @key
      openssl_cipher.iv = @iv if @iv
      result = openssl_cipher.update(string.to_s)
      result << openssl_cipher.final
    end

  end

end