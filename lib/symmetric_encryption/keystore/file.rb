module SymmetricEncryption
  module Keystore
    class File
      attr_accessor :file_name, :key_encryption_key

      # Stores the Encryption key in a file.
      # Secures the Encryption key by encrypting it with a key encryption key.
      def initialize(file_name:, key_encryption_key:)
        @file_name          = file_name
        @key_encryption_key = key_encryption_key

        # TODO: Validate that file is not globally readable.
        raise(SymmetricEncryption::ConfigError, "Symmetric Encryption key file: '#{file_name}' not found") unless ::File.exist?(file_name)
      end

      # Returns the Encryption key in the clear.
      def read
        key_encryption_key.decrypt(read_from_file)
      end

      # Write the encrypted Encryption key to file.
      def write(key)
        write_to_file(key_encryption_key.encrypt(key))
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
        ::File.rename(file_name, "#{file_name}.#{Time.now.to_i}") if ::File.exist?(file_name)
        ::File.open(file_name, 'wb') { |file| file.write(data) }
      end
    end
  end
end
