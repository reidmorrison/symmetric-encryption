module SymmetricEncryption
  module Utils
    module Files
      private

      attr_reader :file_name

      def read_file_and_decode(file_name)
        raise(SymmetricEncryption::ConfigError, "file_name is mandatory for each key_file entry") unless file_name

        raise(SymmetricEncryption::ConfigError, "File #{file_name} could not be found") unless ::File.exist?(file_name)

        # TODO: Validate that file is not globally readable.
        decode64(read_from_file(file_name))
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
      def write_to_file(file_name, data)
        key_path = ::File.dirname(file_name)
        ::FileUtils.mkdir_p(key_path) unless ::File.directory?(key_path)
        ::File.rename(file_name, "#{file_name}.#{Time.now.to_i}") if ::File.exist?(file_name)
        ::File.open(file_name, "wb", 0o600) { |file| file.write(data) }
      end

      # Read from the file, raising an exception if it is not found
      def read_from_file(file_name)
        ::File.open(file_name, "rb", &:read)
      rescue Errno::ENOENT
        raise(SymmetricEncryption::ConfigError, "Symmetric Encryption key file: '#{file_name}' not found or readable")
      end
    end
  end
end
