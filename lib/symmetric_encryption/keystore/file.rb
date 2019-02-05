module SymmetricEncryption
  module Keystore
    class File
      attr_accessor :file_name, :key_encrypting_key

      # Returns [Hash] a new keystore configuration after generating the data key.
      #
      # Increments the supplied version number by 1.
      def self.generate_data_key(key_path:, cipher_name:, app_name:, environment:, version: 0, dek: nil, **args)
        version >= 255 ? (version = 1) : (version += 1)

        dek ||= SymmetricEncryption::Key.new(cipher_name: cipher_name)
        kek   = SymmetricEncryption::Key.new(cipher_name: cipher_name)
        kekek = SymmetricEncryption::Key.new(cipher_name: cipher_name)

        dek_file_name = ::File.join(key_path, "#{app_name}_#{environment}_v#{version}.encrypted_key")
        new(key_filename: dek_file_name, key_encrypting_key: kek).write(dek.key)

        kekek_file_name = ::File.join(key_path, "#{app_name}_#{environment}_v#{version}.kekek")
        new(key_filename: kekek_file_name).write(kekek.key)

        {
          keystore:           :file,
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
      def initialize(key_filename:, key_encrypting_key: nil)
        @file_name          = key_filename
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
        ::File.open(file_name, 'rb', &:read)
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
