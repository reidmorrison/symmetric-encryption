# The key, iv and encrypted data are handled in their raw form, with no encoding.
module SymmetricEncryption
  class Key
    attr_reader :key, :iv, :cipher_name, :version

    def initialize(key: :random, iv: :random, cipher_name: 'aes-256-cbc', version: 1)
      @key         = key == :random ? ::OpenSSL::Cipher.new(cipher_name).random_key : key
      @iv          = iv == :random ? ::OpenSSL::Cipher.new(cipher_name).random_iv : iv
      @cipher_name = cipher_name
      @version     = version
    end

    def encrypt(string, auth_data: '', compress: false)
      return if string.nil?

      string = string.to_s
      return string if string.empty?

      # Creates a new OpenSSL::Cipher with every call so that this key instance is thread-safe.
      cipher = ::OpenSSL::Cipher.new(cipher_name)
      cipher.encrypt
      cipher.key       = key
      cipher.iv        = iv
      cipher.auth_data = auth_data if cipher.authenticated?

      encrypted = cipher.update(string)
      encrypted << cipher.final

      auth_tag = cipher.authenticated? ? cipher.auth_tag : nil

      header = Header.new(
        version:     version,
        compress:    compress,
        iv:          iv,
        key:         key,
        cipher_name: cipher_name,
        auth_tag:    auth_tag
      )
      header.to_s

    end

    def decrypt(encrypted_string, auth_data: '')
      return if encrypted_string.nil?

      encrypted_string = encrypted_string.to_s
      encrypted_string.force_encoding(SymmetricEncryption::BINARY_ENCODING)
      return encrypted_string if encrypted_string.empty?

      # Creates a new OpenSSL::Cipher with every call so that this key instance is thread-safe.
      cipher = ::OpenSSL::Cipher.new(cipher_name)
      cipher.decrypt
      cipher.key       = key
      cipher.iv        = iv
      cipher.auth_data = auth_data if cipher.authenticated?

      result = cipher.update(encrypted_string)
      result << cipher.final
    end
  end
end
