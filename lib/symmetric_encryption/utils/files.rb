module SymmetricEncryption
  module Utils
    module Files
      private

      attr_reader :file_name

      # Returns [Utils::FileAccess] what the key files are expected to look like on disk.
      # Keystores that hold their keys in files build this from their configuration, so that the
      # environment the key files are deployed into can be described where it differs from the
      # default of readable by its owner alone.
      def file_access
        @file_access ||= Utils::FileAccess.new
      end

      def read_file_and_decode(file_name)
        raise(SymmetricEncryption::ConfigError, "file_name is mandatory for each key_file entry") unless file_name

        raise(SymmetricEncryption::ConfigError, "File #{file_name} could not be found") unless ::File.exist?(file_name)

        decode64(read_key_file(file_name))
      end

      def write_encoded_to_file(file_name, encrypted_data_key)
        write_to_file(file_name, encode64(encrypted_data_key))
      end

      def encode64(data)
        Base64.strict_encode64(data)
      end

      def decode64(data)
        Base64.strict_decode64(data)
      end

      # Write to the supplied file_name, backing up the existing file if present
      def write_to_file(file_name, data, permission: file_access.permission)
        key_path = ::File.dirname(file_name)
        ::FileUtils.mkdir_p(key_path) unless ::File.directory?(key_path)
        ::File.rename(file_name, "#{file_name}.#{Time.now.to_i}") if ::File.exist?(file_name)
        ::File.open(file_name, "wb", permission) { |file| file.write(data) }
        # The umask can clear bits from the mode above, so apply it explicitly.
        ::FileUtils.chmod(permission, file_name)
      end

      # Read the key file, once it is only readable by who the configuration says it is.
      def read_key_file(file_name)
        file_access.verify!(file_name)
        read_from_file(file_name)
      end

      # Read from the file, raising an exception if it is not found
      def read_from_file(file_name)
        ::File.binread(file_name)
      rescue Errno::ENOENT
        raise(SymmetricEncryption::ConfigError, "Symmetric Encryption key file: '#{file_name}' not found or readable")
      end
    end
  end
end
