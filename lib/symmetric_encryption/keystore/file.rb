module SymmetricEncryption
  module Keystore
    class File
      attr_accessor :file_name, :key_encrypting_key

      # Returns [Hash] initial configuration.
      # Generates the encrypted key file for every environment except development and test.
      def self.new_config(key_path: '/etc/symmetric-encryption',
        app_name: 'symmetric-encryption',
        environments: %i(development test release production),
        cipher_name: 'aes-256-cbc')

        configs = {}
        environments.each do |environment|
          environment          = environment.to_sym
          configs[environment] =
            if %i(development test).include?(environment)
              Memory.dev_config
            else
              rsa_key                  = SymmetricEncryption::KeyEncryptingKey.generate_rsa_key
              key_encrypting_key       = SymmetricEncryption::KeyEncryptingKey.new(rsa_key)
              cfg                      = new_cipher(key_path: key_path, cipher_name: cipher_name, key_encrypting_key: key_encrypting_key, app_name: app_name, environment: environment)
              cfg[:key_encrypting_key] = rsa_key
              {
                ciphers: [cfg]
              }
            end
        end
        configs
      end

      # Returns [Hash] a new cipher, and writes its encrypted key file.
      #
      # Increments the supplied version number by 1.
      def self.new_cipher(key_path:, cipher_name:, key_encrypting_key:, app_name:, environment:, version: 0)
        version >= 255 ? (version = 1) : (version += 1)

        cipher        = Cipher.new(cipher_name: cipher_name, key_encrypting_key: key_encrypting_key)
        encrypted_key = cipher.encrypted_key
        iv            = cipher.iv

        file_name = ::File.join(key_path, "#{app_name}_#{environment}_v#{version}.key")
        new(file_name: file_name, key_encrypting_key: key_encrypting_key).write_encrypted(encrypted_key)

        {
          key_filename: file_name,
          iv:           iv,
          cipher_name:  cipher_name,
          version:      version
        }
      end

      # Stores the Encryption key in a file.
      # Secures the Encryption key by encrypting it with a key encryption key.
      def initialize(file_name:, key_encrypting_key:)
        @file_name          = file_name
        @key_encrypting_key = key_encrypting_key
      end

      # Returns the Encryption key in the clear.
      def read
        # TODO: Validate that file is not globally readable.
        raise(SymmetricEncryption::ConfigError, "Symmetric Encryption key file: '#{file_name}' not found") unless ::File.exist?(file_name)

        key_encrypting_key.decrypt(read_from_file)
      end

      # Encrypt and write the key to file.
      def write(key)
        write_to_file(key_encrypting_key.encrypt(key))
      end

      # Write an already encrypted key to file.
      def write_encrypted(encrypted_key)
        write_to_file(encrypted_key)
      end

      private

      # Read from the file, raising an exception if it is not found
      def read_from_file
        ::File.open(file_name, 'rb') { |f| f.read }
      rescue Errno::ENOENT
        raise(SymmetricEncryption::ConfigError, "Symmetric Encryption key file: '#{file_name}' not found or readable")
      end

      # Write to the supplied file_name, backing up the existing file if present
      def write_to_file(data)
        key_path = ::File.dirname(file_name)
        ::FileUtils.mkdir_p(key_path) unless ::File.directory?(key_path)
        ::File.rename(file_name, "#{file_name}.#{Time.now.to_i}") if ::File.exist?(file_name)
        ::File.open(file_name, 'wb') { |file| file.write(data) }
      end

    end
  end
end
