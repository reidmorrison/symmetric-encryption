# The key, iv and encrypted data are handled in their raw form, with no encoding.
module SymmetricEncryption
  class Key
    attr_reader :key, :iv, :cipher_name

    # Returns [Key] from cipher data usually extracted from the configuration file.
    #
    # Supports N level deep key encrypting keys.
    #
    # Configuration keys:
    # * key
    # * encrypted_key
    # * key_filename
    def self.from_config(key: nil, key_filename: nil, encrypted_key: nil, key_env_var: nil,
      iv:, key_encrypting_key: nil, cipher_name: 'aes-256-cbc')

      if key_encrypting_key.is_a?(Hash)
        # Recurse up the chain returning the parent key_encrypting_key
        key_encrypting_key = from_config(cipher_name: cipher_name, **key_encrypting_key)
      end

      key ||=
        if encrypted_key
          raise(ArgumentError, "Missing mandatory :key_encrypting_key when config includes :encrypted_key") unless key_encrypting_key
          Keystore::Memory.new(encrypted_key: encrypted_key, key_encrypting_key: key_encrypting_key).read
        elsif key_filename
          Keystore::File.new(file_name: key_filename, key_encrypting_key: key_encrypting_key).read
        elsif key_env_var
          raise(ArgumentError, "Missing mandatory :key_encrypting_key when config includes :key_env_var") unless key_encrypting_key
          Keystore::Environment.new(key_env_var: key_env_var, key_encrypting_key: key_encrypting_key).read
        end

      new(key: key, iv: iv, cipher_name: cipher_name)
    end

    # Migrate a prior config.
    #
    # Note:
    # * The config cannot be saved back to the config file once
    #   migrated, without generating new Key Encrypting Keys.
    # * Only run this migration in the target environment so that the
    #   current key encrypting files are present.
    def self.migrate_config!(config)
      # Backward compatibility - Deprecated
      private_rsa_key = config.delete(:private_rsa_key)

      # Migrate old encrypted_iv
      if (encrypted_iv = config.delete(:encrypted_iv)) && private_rsa_key
        encrypted_iv = RSAKey.new(private_rsa_key).decrypt(encrypted_iv)
        config[:iv]  = ::Base64.decode64(encrypted_iv)
      end

      # Migrate old iv_filename
      if (file_name = config.delete(:iv_filename)) && private_rsa_key
        encrypted_iv = File.read(file_name)
        config[:iv]  = RSAKey.new(private_rsa_key).decrypt(encrypted_iv)
      end

      # Backward compatibility - Deprecated
      config[:key_encrypting_key] = RSAKey.new(private_rsa_key) if private_rsa_key

      # Migrate old encrypted_key to new binary format
      if (encrypted_key = config[:encrypted_key]) && private_rsa_key
        config[:encrypted_key] = ::Base64.decode64(encrypted_key)
      end
    end

    def initialize(key: :random, iv: :random, cipher_name: 'aes-256-cbc')
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
