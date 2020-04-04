module SymmetricEncryption
  module Keystore
    class File
      include Utils::Files
      ALLOWED_PERMISSIONS = %w[100600 100400].freeze

      attr_accessor :file_name, :key_encrypting_key

      # Returns [Hash] a new keystore configuration after generating the data key.
      #
      # Increments the supplied version number by 1.
      def self.generate_data_key(key_path:, cipher_name:, app_name:, environment:, version: 0, dek: nil, **_args)
        version >= 255 ? (version = 1) : (version += 1)

        dek ||= SymmetricEncryption::Key.new(cipher_name: cipher_name)
        kek = SymmetricEncryption::Key.new(cipher_name: cipher_name)
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
        unless ::File.exist?(file_name)
          raise(SymmetricEncryption::ConfigError,
                "Symmetric Encryption key file: '#{file_name}' not found")
        end
        unless correct_permissions?
          raise(SymmetricEncryption::ConfigError,
                "Symmetric Encryption key file '#{file_name}' has the wrong "\
                "permissions: #{::File.stat(file_name).mode.to_s(8)}. Expected 100600 or 100400.")
        end
        unless owned?
          raise(SymmetricEncryption::ConfigError,
                "Symmetric Encryption key file '#{file_name}' has the wrong "\
                "owner (#{stat.uid}) or group (#{stat.gid}). "\
                "Expected it to be owned by current user "\
                "#{ENV['USER'] || ENV['USERNAME']}.")
        end

        data = read_from_file(file_name)
        key_encrypting_key ? key_encrypting_key.decrypt(data) : data
      end

      # Encrypt and write the key to file.
      def write(key)
        data = key_encrypting_key ? key_encrypting_key.encrypt(key) : key
        write_to_file(file_name, data)
      end

      private

      # Returns true if the file is owned by the user running this code and it
      # has the correct mode - readable and writable by its owner and no one
      # else, much like the keys one has in ~/.ssh
      def correct_permissions?
        ALLOWED_PERMISSIONS.include?(stat.mode.to_s(8))
      end

      def owned?
        stat.owned?
      end

      def stat
        ::File.stat(file_name)
      end
    end
  end
end
