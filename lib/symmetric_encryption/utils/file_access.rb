require "etc"
module SymmetricEncryption
  module Utils
    # What a key file is expected to look like on disk, and the check that it does.
    #
    # Anyone who can read a key file can decrypt everything that was encrypted with it, so by
    # default a key file has to be readable by its owner alone, and owned by the user running this
    # code. Environments that decide these themselves supply what they produce instead, and the key
    # file is verified against that. For example a read-only Kubernetes secret volume, which mounts
    # its files as 0644 owned by root, whatever user the container itself runs as.
    #
    # Notes:
    # * Naming what is expected is not the same as not checking it. Everything else is still
    #   rejected.
    # * Anything less restrictive than the default lets other users on that machine read the
    #   encryption key, so relax it only where the surrounding environment provides the protection
    #   instead.
    class FileAccess
      # Permissions a key file is allowed to have when the configuration does not supply its own.
      #
      # The first entry is also the permission that new key files are created with.
      DEFAULT_PERMISSIONS = [0o600, 0o400].freeze

      attr_reader :permissions, :owners, :groups

      # permissions: [Integer|String|Array<Integer|String>]
      #   The permissions that the key file is allowed to have, as octal file modes without the
      #   file type bits. Supply them as an Integer, `0o644`, or as a String, `"0644"`.
      #   Supply an Array when more than one is acceptable. New key files are created with the
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
      def initialize(permissions: nil, owner: nil, group: nil)
        @permissions = parse_permissions(permissions)
        @owners      = parse_ids(owner, :owner) { |name| Etc.getpwnam(name).uid }
        @groups      = parse_ids(group, :group) { |name| Etc.getgrnam(name).gid }
      end

      # Returns [Integer] the permission that new key files are created with.
      def permission
        permissions.first
      end

      # Raises [SymmetricEncryption::ConfigError] when the key file is not what the configuration
      # says it should be. The file has to exist, `File.stat` raises otherwise.
      # Returns true so that callers cannot mistake it for the contents of the file.
      def verify!(file_name) # rubocop:disable Naming/PredicateMethod
        stat = ::File.stat(file_name)

        verify_permissions!(file_name, stat)
        verify_owner!(file_name, stat)
        verify_group!(file_name, stat)
        true
      end

      private

      def verify_permissions!(file_name, stat)
        mode = stat.mode & 0o7777
        return if permissions.include?(mode)

        raise(SymmetricEncryption::ConfigError,
              "Symmetric Encryption key file '#{file_name}' has the wrong " \
              "permissions: #{format_permission(mode)}. Expected #{expected_permissions}.")
      end

      # By default the key file has to be owned by the user running this code, much like the keys
      # one has in ~/.ssh
      def verify_owner!(file_name, stat)
        return if owners.nil? ? stat.owned? : owners.include?(stat.uid)

        raise(SymmetricEncryption::ConfigError,
              "Symmetric Encryption key file '#{file_name}' has the wrong " \
              "owner: #{format_owner(stat.uid)}. Expected #{expected_owners}.")
      end

      # The group is not checked unless the configuration names one.
      def verify_group!(file_name, stat)
        return if groups.nil? || groups.include?(stat.gid)

        raise(SymmetricEncryption::ConfigError,
              "Symmetric Encryption key file '#{file_name}' has the wrong " \
              "group: #{format_group(stat.gid)}. Expected #{expected_groups}.")
      end

      # Returns [Array<Integer>] the supplied permissions as octal file modes.
      def parse_permissions(permissions)
        return DEFAULT_PERMISSIONS if permissions.nil?

        modes = Array(permissions).collect { |permission| parse_permission(permission) }
        raise(SymmetricEncryption::ConfigError, empty_list_message(:permissions)) if modes.empty?

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
        "Invalid Symmetric Encryption :permissions #{permission.inspect}. " \
          "Supply an octal file mode, without the file type bits, as an Integer, 0o644, or a String, \"0644\"."
      end

      # Returns [Array<Integer>|nil] the supplied names, or ids, as numeric ids.
      # Returns nil when nothing was supplied, which each check reads as its own default.
      def parse_ids(values, option, &resolver)
        return if values.nil?

        ids = Array(values).collect { |value| parse_id(value, option, &resolver) }
        raise(SymmetricEncryption::ConfigError, empty_list_message(option)) if ids.empty?

        ids.freeze
      end

      def empty_list_message(option)
        "Symmetric Encryption was supplied an empty list of :#{option}."
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
                  "Unknown Symmetric Encryption :#{option} #{value.inspect}. There is no such #{option} on this " \
                  "machine. Supply its numeric id instead when the name cannot be resolved everywhere this " \
                  "configuration is loaded.")
          rescue NotImplementedError, NoMethodError
            raise(SymmetricEncryption::ConfigError,
                  "Cannot look up Symmetric Encryption :#{option} #{value.inspect} on this platform. " \
                  "Supply its numeric id instead.")
          end
        else
          raise(SymmetricEncryption::ConfigError, invalid_id_message(value, option))
        end
      end

      def invalid_id_message(value, option)
        "Invalid Symmetric Encryption :#{option} #{value.inspect}. " \
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
