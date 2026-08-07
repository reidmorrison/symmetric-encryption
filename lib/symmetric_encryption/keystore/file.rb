module SymmetricEncryption
  module Keystore
    class File
      include Utils::Files

      # File permissions a key file is allowed to have when the configuration does not supply its own.
      #
      # The first entry is also the permission that new key files are created with.
      DEFAULT_PERMISSIONS = [0o600, 0o400].freeze

      attr_accessor :file_name, :key_encrypting_key
      attr_reader :permissions

      # Returns [Hash] a new keystore configuration after generating the data key.
      #
      # Increments the supplied version number by 1.
      #
      # permissions: [Integer|String|Array<Integer|String>]
      #   Permissions to create the key files with, and to record in the returned configuration.
      #   See `#initialize`.
      def self.generate_data_key(key_path:, cipher_name:, app_name:, environment:, version: 0, dek: nil,
                                 permissions: nil, **_args)
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

        # Both key files are written with these permissions, so both entries have to verify against them.
        if permissions
          config[:permissions] = permissions
          config[:key_encrypting_key][:key_encrypting_key][:permissions] = permissions
        end
        config
      end

      # Stores the Encryption key in a file.
      # Secures the Encryption key by encrypting it with a key encryption key.
      #
      # permissions: [Integer|String|Array<Integer|String>]
      #   The permissions that the key file is allowed to have, as octal file modes without the
      #   file type bits. Supply them as an Integer, `0o644`, or as a String, `"0644"`.
      #   Supply an Array when more than one is acceptable. `#write` creates key files with the
      #   first entry, so list the most restrictive permission first.
      #   Default: 0600, or 0400.
      #
      # Notes:
      # * Only supply this when something outside of this application dictates the permissions of
      #   the key file. For example a read-only Kubernetes secret volume, which always mounts its
      #   files as 0644.
      # * Anything less restrictive than the default lets other users on that machine read the
      #   encryption key, so relax it only where the surrounding environment provides the
      #   protection instead.
      def initialize(key_filename:, key_encrypting_key: nil, permissions: nil)
        @file_name          = key_filename
        @key_encrypting_key = key_encrypting_key
        @permissions        = parse_permissions(permissions)
      end

      # Returns the Encryption key in the clear.
      def read
        unless ::File.exist?(file_name)
          raise(SymmetricEncryption::ConfigError,
                "Symmetric Encryption key file: '#{file_name}' not found")
        end
        unless correct_permissions?
          raise(SymmetricEncryption::ConfigError,
                "Symmetric Encryption key file '#{file_name}' has the wrong " \
                "permissions: #{format_permission(current_permission)}. Expected #{expected_permissions}.")
        end
        unless owned?
          raise(SymmetricEncryption::ConfigError,
                "Symmetric Encryption key file '#{file_name}' has the wrong " \
                "owner (#{stat.uid}) or group (#{stat.gid}). " \
                "Expected it to be owned by current user " \
                "#{ENV['USER'] || ENV.fetch('USERNAME', nil)}.")
        end

        data = read_from_file(file_name)
        key_encrypting_key ? key_encrypting_key.decrypt(data) : data
      end

      # Encrypt and write the key to file.
      def write(key)
        data = key_encrypting_key ? key_encrypting_key.encrypt(key) : key
        write_to_file(file_name, data, permission: permissions.first)
      end

      private

      # Returns true if the file has one of the permissions it is allowed to have.
      # By default readable and writable by its owner and no one else, much like the
      # keys one has in ~/.ssh
      def correct_permissions?
        permissions.include?(current_permission)
      end

      # Returns [Integer] the current permissions of the key file, without the file type bits.
      def current_permission
        stat.mode & 0o7777
      end

      def owned?
        stat.owned?
      end

      def stat
        ::File.stat(file_name)
      end

      # Returns [Array<Integer>] the supplied permissions as octal file modes.
      def parse_permissions(permissions)
        return DEFAULT_PERMISSIONS if permissions.nil?

        modes = Array(permissions).collect { |permission| parse_permission(permission) }
        if modes.empty?
          raise(SymmetricEncryption::ConfigError,
                "Symmetric Encryption key file '#{file_name}' was supplied an empty list of :permissions.")
        end

        modes.freeze
      end

      # Returns [Integer] the supplied octal permission as a file mode.
      def parse_permission(permission)
        mode =
          case permission
          when Integer
            permission
          when String
            begin
              Integer(permission, 8)
            rescue ArgumentError
              raise(SymmetricEncryption::ConfigError, invalid_permission_message(permission))
            end
          else
            raise(SymmetricEncryption::ConfigError, invalid_permission_message(permission))
          end

        raise(SymmetricEncryption::ConfigError, invalid_permission_message(permission)) unless (0..0o7777).cover?(mode)

        mode
      end

      def invalid_permission_message(permission)
        "Invalid Symmetric Encryption :permissions #{permission.inspect} for key file '#{file_name}'. " \
          "Supply an octal file mode, without the file type bits, as an Integer, 0o644, or a String, \"0644\"."
      end

      # Returns [String] the permissions the key file is allowed to have, for use in an error message.
      def expected_permissions
        permissions.collect { |mode| format_permission(mode) }.join(" or ")
      end

      def format_permission(mode)
        format("%04o", mode)
      end
    end
  end
end
