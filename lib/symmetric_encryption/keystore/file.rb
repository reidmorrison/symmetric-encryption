module SymmetricEncryption
  module Keystore
    class File
      attr_accessor :filename, :key_encryption_key

      # Stores the Encryption key in a file.
      # Secures the Encryption key by encrypting it with a key encryption key.
      def initialize(filename:, key_encryption_key:)
        @filename           = filename
        @key_encryption_key = key_encryption_key

        # TODO: Validate that file is not globally readable.
        raise(SymmetricEncryption::ConfigError, "Symmetric Encryption key file: '#{filename}' not found") unless File.exist?
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
        File.open(filename, 'rb') { |f| f.read }
      rescue Errno::ENOENT
        raise(SymmetricEncryption::ConfigError, "Symmetric Encryption key file: '#{filename}' not found or readable")
      end

      # Write to the supplied filename, backing up the existing file if present
      def write_to_file(data)
        File.rename(filename, "#{filename}.#{Time.now.to_i}") if File.exist?(filename)
        File.open(filename, 'wb') { |file| file.write(data) }
      end
    end
  end
end
