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
    attr_reader :cipher, :version

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
      @version = parms[:version]
    end

    # AES Symmetric Encryption of supplied string
    #  Returns result as a Base64 encoded string
    #  Returns nil if the supplied str is nil
    #  Returns "" if it is a string and it is empty
    #
    #  options:
    #    :encoding
    #       :base64 Return as a base64 encoded string
    #       :binary Return as raw binary data string. Note: String can contain embedded nulls
    #      Default: :base64
    #    :compress
    #      [true|false] Whether or not to compress the data _before_ encrypting
    #      Default: false
    def encrypt(str)
      return if str.nil?
      buf = str.to_s
      return str if buf.empty?
      crypt(:encrypt, buf)
    end

    # AES Symmetric Decryption of supplied string
    #  Returns decrypted string
    #  Returns nil if the supplied str is nil
    #  Returns "" if it is a string and it is empty
    def decrypt(str)
      return if str.nil?
      buf = str.to_s
      return str if buf.empty?
      crypt(:decrypt, buf)
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