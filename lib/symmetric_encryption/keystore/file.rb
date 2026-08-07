module SymmetricEncryption
  module Keystore
    class File
      include Utils::Files

      attr_accessor :file_name, :key_encrypting_key

      # Returns [Hash] a new keystore configuration after generating the data key.
      #
      # Increments the supplied version number by 1.
      #
      # permissions: [Integer|String|Array<Integer|String>]
      #   Permissions to create the key files with, and to record in the returned configuration.
      #   See `SymmetricEncryption::Utils::FileAccess`.
      #
      # owner: [Integer|String|Array<Integer|String>]
      # group: [Integer|String|Array<Integer|String>]
      #   Owner and group to record in the returned configuration.
      #   See `SymmetricEncryption::Utils::FileAccess`.
      #   The key files are not changed to match, since that requires privileges this process is
      #   not expected to have. They describe the environment the key files are deployed into.
      def self.generate_data_key(key_path:, cipher_name:, app_name:, environment:, version: 0, dek: nil,
                                 permissions: nil, owner: nil, group: nil, **_args)
        version >= 255 ? (version = 1) : (version += 1)

        dek ||= SymmetricEncryption::Key.new(cipher_name: cipher_name)
        kek = SymmetricEncryption::Key.new(cipher_name: cipher_name)
        kekek = SymmetricEncryption::Key.new(cipher_name: cipher_name)

        dek_file_name = ::File.join(key_path, "#{app_name}_#{environment}_v#{version}.encrypted_key")
        new(key_filename: dek_file_name, key_encrypting_key: kek, permissions: permissions).write(dek.key)

        kekek_file_name = ::File.join(key_path, "#{app_name}_#{environment}_v#{version}.kekek")
        new(key_filename: kekek_file_name, permissions: permissions).write(kekek.key)

        config = {
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

        # Both key files are created side by side, so both entries carry the same expectations.
        kekek_config = config[:key_encrypting_key][:key_encrypting_key]
        {permissions: permissions, owner: owner, group: group}.each_pair do |name, value|
          next if value.nil?

          config[name]       = value
          kekek_config[name] = value
        end
        config
      end

      # Stores the Encryption key in a file.
      # Secures the Encryption key by encrypting it with a key encryption key.
      #
      # permissions, owner, group:
      #   What the key file is expected to look like on disk.
      #   See `SymmetricEncryption::Utils::FileAccess`.
      def initialize(key_filename:, key_encrypting_key: nil, permissions: nil, owner: nil, group: nil)
        @file_name          = key_filename
        @key_encrypting_key = key_encrypting_key
        @file_access        = Utils::FileAccess.new(permissions: permissions, owner: owner, group: group)
      end

      # Returns the Encryption key in the clear.
      def read
        unless ::File.exist?(file_name)
          raise(SymmetricEncryption::ConfigError,
                "Symmetric Encryption key file: '#{file_name}' not found")
        end

        data = read_key_file(file_name)
        key_encrypting_key ? key_encrypting_key.decrypt(data) : data
      end

      # Encrypt and write the key to file.
      def write(key)
        data = key_encrypting_key ? key_encrypting_key.encrypt(key) : key
        write_to_file(file_name, data)
      end
    end
  end
end
