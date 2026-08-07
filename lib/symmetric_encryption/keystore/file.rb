require "etc"
module SymmetricEncryption
  module Keystore
    class File
      include Utils::Files

      # File permissions a key file is allowed to have when the configuration does not supply its own.
      #
      # The first entry is also the permission that new key files are created with.
      DEFAULT_PERMISSIONS = [0o600, 0o400].freeze

      attr_accessor :file_name, :key_encrypting_key
      attr_reader :permissions, :owners, :groups

      # Returns [Hash] a new keystore configuration after generating the data key.
      #
      # Increments the supplied version number by 1.
      #
      # permissions: [Integer|String|Array<Integer|String>]
      #   Permissions to create the key files with, and to record in the returned configuration.
      #   See `#initialize`.
      #
      # owner: [Integer|String|Array<Integer|String>]
      # group: [Integer|String|Array<Integer|String>]
      #   Owner and group to record in the returned configuration. See `#initialize`.
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
      # permissions: [Integer|String|Array<Integer|String>]
      #   The permissions that the key file is allowed to have, as octal file modes without the
      #   file type bits. Supply them as an Integer, `0o644`, or as a String, `"0644"`.
      #   Supply an Array when more than one is acceptable. `#write` creates key files with the
      #   first entry, so list the most restrictive permission first.
      #   Default: 0600, or 0400.
      #
      # owner: [Integer|String|Array<Integer|String>]
      #   The user that the key file is expected to be owned by, as a user name, `"root"`, or as a
      #   numeric user id, `0`. Supply an Array when more than one is acceptable.
      #   Default: the user running this code.
      #
      # group: [Integer|String|Array<Integer|String>]
      #   The group that the key file is expected to belong to, as a group name, `"deploy"`, or as
      #   a numeric group id, `20`. Supply an Array when more than one is acceptable.
      #   Default: the group is not checked.
      #
      # Notes:
      # * Only supply these when something outside of this application dictates the permissions or
      #   the ownership of the key file. For example a read-only Kubernetes secret volume, which
      #   mounts its files as 0644, owned by root, whatever user the container runs as.
      # * Anything less restrictive than the default lets other users on that machine read the
      #   encryption key, so relax it only where the surrounding environment provides the
      #   protection instead.
      # * Naming the expected owner is not the same as not checking it. The key file still has to
      #   be owned by who the configuration says it is.
      def initialize(key_filename:, key_encrypting_key: nil, permissions: nil, owner: nil, group: nil)
        @file_name          = key_filename
        @key_encrypting_key = key_encrypting_key
        @permissions        = parse_permissions(permissions)
        @owners             = parse_ids(owner, :owner) { |name| Etc.getpwnam(name).uid }
        @groups             = parse_ids(group, :group) { |name| Etc.getgrnam(name).gid }
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
        unless correct_owner?
          raise(SymmetricEncryption::ConfigError,
                "Symmetric Encryption key file '#{file_name}' has the wrong " \
                "owner: #{format_owner(stat.uid)}. Expected #{expected_owners}.")
        end
        unless correct_group?
          raise(SymmetricEncryption::ConfigError,
                "Symmetric Encryption key file '#{file_name}' has the wrong " \
                "group: #{format_group(stat.gid)}. Expected #{expected_groups}.")
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

      # Returns true if the file is owned by one of the users it is allowed to be owned by.
      # By default the user running this code, much like the keys one has in ~/.ssh
      def correct_owner?
        return stat.owned? if owners.nil?

        owners.include?(stat.uid)
      end

      # Returns true if the file belongs to one of the groups it is allowed to belong to.
      # The group is not checked unless the configuration names one.
      def correct_group?
        return true if groups.nil?

        groups.include?(stat.gid)
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

      # Returns [Array<Integer>|nil] the supplied names, or ids, as numeric ids.
      # Returns nil when nothing was supplied, which each check reads as its own default.
      def parse_ids(values, option, &resolver)
        return if values.nil?

        ids = Array(values).collect { |value| parse_id(value, option, &resolver) }
        if ids.empty?
          raise(SymmetricEncryption::ConfigError,
                "Symmetric Encryption key file '#{file_name}' was supplied an empty list of :#{option}.")
        end

        ids.freeze
      end

      # Returns [Integer] the supplied name, or id, as a numeric id.
      def parse_id(value, option)
        case value
        when Integer
          raise(SymmetricEncryption::ConfigError, invalid_id_message(value, option)) if value.negative?

          value
        when String
          begin
            yield(value)
          rescue ArgumentError
            raise(SymmetricEncryption::ConfigError,
                  "Unknown Symmetric Encryption :#{option} #{value.inspect} for key file '#{file_name}'. " \
                  "There is no such #{option} on this machine. Supply its numeric id instead when the name " \
                  "cannot be resolved everywhere this configuration is loaded.")
          rescue NotImplementedError, NoMethodError
            raise(SymmetricEncryption::ConfigError,
                  "Cannot look up Symmetric Encryption :#{option} #{value.inspect} for key file " \
                  "'#{file_name}' on this platform. Supply its numeric id instead.")
          end
        else
          raise(SymmetricEncryption::ConfigError, invalid_id_message(value, option))
        end
      end

      def invalid_id_message(value, option)
        "Invalid Symmetric Encryption :#{option} #{value.inspect} for key file '#{file_name}'. " \
          "Supply a name, such as \"root\", or its numeric id, such as 0."
      end

      # Returns [String] the permissions the key file is allowed to have, for use in an error message.
      def expected_permissions
        permissions.collect { |mode| format_permission(mode) }.join(" or ")
      end

      # Returns [String] the owners the key file is allowed to have, for use in an error message.
      def expected_owners
        return "it to be owned by the current user, #{format_owner(Process.uid)}" if owners.nil?

        owners.collect { |uid| format_owner(uid) }.join(" or ")
      end

      # Returns [String] the groups the key file is allowed to have, for use in an error message.
      def expected_groups
        groups.collect { |gid| format_group(gid) }.join(" or ")
      end

      def format_permission(mode)
        format("%04o", mode)
      end

      def format_owner(uid)
        format_id(uid) { Etc.getpwuid(uid).name }
      end

      def format_group(gid)
        format_id(gid) { Etc.getgrgid(gid).name }
      end

      # Returns [String] the id, named as well when the name can be resolved on this machine.
      def format_id(numeric_id)
        name =
          begin
            yield
          rescue ArgumentError, NotImplementedError, NoMethodError
            nil
          end
        name ? "#{name} (#{numeric_id})" : numeric_id.to_s
      end
    end
  end
end
