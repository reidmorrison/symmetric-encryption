# The key, iv and encrypted data are handled in their raw form, with no encoding.
module SymmetricEncryption
  class Key
    attr_reader :key, :iv, :cipher_name

    def initialize(key: :random, iv: :random, cipher_name: "aes-256-cbc")
      @key         = key == :random ? ::OpenSSL::Cipher.new(cipher_name).random_key : key
      @iv          = iv == :random ? ::OpenSSL::Cipher.new(cipher_name).random_iv : iv
      @cipher_name = cipher_name
    end

    def encrypt(string)
      return if string.nil?

      string = string.to_s
      return string if string.empty?

      # Creates a new OpenSSL::Cipher with every call so that this key instance is thread-safe.
      openssl_cipher = ::OpenSSL::Cipher.new(cipher_name)
      openssl_cipher.encrypt
      openssl_cipher.key = key
      openssl_cipher.iv  = iv

      result = openssl_cipher.update(string)
      result << openssl_cipher.final
    end

    def decrypt(encrypted_string)
      return if encrypted_string.nil?

      encrypted_string = encrypted_string.to_s
      encrypted_string.force_encoding(SymmetricEncryption::BINARY_ENCODING)
      return encrypted_string if encrypted_string.empty?

      # Creates a new OpenSSL::Cipher with every call so that this key instance is thread-safe.
      openssl_cipher = ::OpenSSL::Cipher.new(cipher_name)
      openssl_cipher.decrypt
      openssl_cipher.key = key
      openssl_cipher.iv  = iv

      result = openssl_cipher.update(encrypted_string)
      result << openssl_cipher.final
    end
  end
end
