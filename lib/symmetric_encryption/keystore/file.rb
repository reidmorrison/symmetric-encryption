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
              Keystore.dev_config
            else
              cfg = new_key_config(key_path: key_path, cipher_name: cipher_name, app_name: app_name, environment: environment)
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
      def self.new_key_config(key_path:, cipher_name:, app_name:, environment:, version: 0, dek: nil)
        version >= 255 ? (version = 1) : (version += 1)

        dek   ||= SymmetricEncryption::Key.new(cipher_name: cipher_name)
        kek   = SymmetricEncryption::Key.new(cipher_name: cipher_name)
        kekek = SymmetricEncryption::Key.new(cipher_name: cipher_name)

        dek_file_name = ::File.join(key_path, "#{app_name}_#{environment}_v#{version}.encrypted_key")
        new(file_name: dek_file_name, key_encrypting_key: kek).write(dek.key)

        kekek_file_name = ::File.join(key_path, "#{app_name}_#{environment}_v#{version}.kekek")
        new(file_name: kekek_file_name).write(kekek.key)

        {
          cipher_name:        dek.cipher_name,
          version:            version,
          key_filename:       dek_file_name,
          iv:                 dek.iv,
          key_encrypting_key: {
            encrypted_key:      kekek.encrypt(kek.key),
            iv:                 kek.iv,
            key_encrypting_key: {
              key_filename: kekek_file_name,
              iv:           kekek.iv
            }
          }
        }
      end

      # Stores the Encryption key in a file.
      # Secures the Encryption key by encrypting it with a key encryption key.
      def initialize(file_name:, key_encrypting_key: nil)
        @file_name          = file_name
        @key_encrypting_key = key_encrypting_key
      end

      # Returns the Encryption key in the clear.
      def read
        # TODO: Validate that file is not globally readable.
        raise(SymmetricEncryption::ConfigError, "Symmetric Encryption key file: '#{file_name}' not found") unless ::File.exist?(file_name)

        data = read_from_file
        key_encrypting_key ? key_encrypting_key.decrypt(data) : data
      end

      # Encrypt and write the key to file.
      def write(key)
        data = key_encrypting_key ? key_encrypting_key.encrypt(key) : key
        write_to_file(data)
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
