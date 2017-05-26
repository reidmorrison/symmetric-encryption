# Used for re-encrypting encrypted passwords stored in configuration files.
#
# Search for any encrypted value and re-encrypt it using the latest encryption key.
# Note:
# * Only works with encrypted values that have the standard header.
#   * The search looks for the header and then replaces the encrypted value.
#
# Example:
#   re_encrypt = SymmetricEncryption::Utils::ReEncryptConfigFiles.new(version: 4)
#   re_encrypt.process_directory('../../**/*.yml')
#
# Notes:
# * Only supports the output from encrypting data.
#   * I.e. Manually adding newlines to base 64 output is not supported.
# * For now only supports one encrypted value per line.
module SymmetricEncryption
  module Utils
    # ReEncrypt files
    #
    #   If a file is encrypted, it is re-encrypted with the cipher that has the highest version number.
    #   A file is already encrypted with the highest version is not re-encrypted.
    #
    #   If a file is not encrypted, the file is searched for any encrypted values, and those values are re-encrypted.
    #
    #   symmetric_encryption --reencrypt "**/*.yml"
    class ReEncryptFiles
      attr_accessor :cipher, :path

      # Parameters:
      #   version: [Integer]
      #     Version of the encryption key to use when re-encrypting the value.
      #     Default: Default cipher ( first in the list of configured ciphers )
      def initialize(version: SymmetricEncryption.cipher.version, path: '**/*.yml')
        @cipher = SymmetricEncryption.cipher(version)
        @path   = path
        raise(ArgumentError, "Undefined encryption key version: #{version}") if @cipher.nil?
      end

      # Re-encrypt the supplied encrypted value with the new cipher
      def re_encrypt(encrypted)
        if unencrypted = SymmetricEncryption.try_decrypt(encrypted)
          cipher.encrypt(unencrypted)
        else
          encrypted
        end
      end

      # Process a single file.
      #
      # Returns [true|false] whether the file was modified
      def re_encrypt_contents(file_name)
        match        = false
        lines        = File.read(file_name)
        output_lines = ''
        r            = regexp
        lines.each_line do |line|
          output_lines <<
            if result = line.match(r)
              encrypted = result[0]
              new_value = re_encrypt(encrypted)
              if new_value != encrypted
                match = true
                line.gsub(encrypted, new_value)
              else
                line
              end
            else
              line
            end
        end
        if match
          File.open(file_name, 'wb') { |file| file.write(output_lines) }
        end
        match
      end

      # Re Encrypt an entire file
      def re_encrypt_file(file_name)
        temp_file_name = "#{file_name}_re_encrypting"
        SymmetricEncryption::Reader.open(file_name) do |source|
          SymmetricEncryption::Writer.encrypt(source: source, target: temp_file_name, compress: true)
        end
      rescue
        File.delete(temp_file_name) if File.exist?(temp_file_name)
        raise
      end

      # Process a directory of files.
      #
      # Parameters:
      #   path: [String]
      #     Search path to look for files in.
      #     Example: '../../**/*.yml'
      def process_directory(path)
        Dir[path].each do |file_name|
          if SymmetricEncryption::Reader.header_present?(file_name)
            re_encrypt_file(file_name)
          else
            re_encrypt_contents(file_name)
          end

        end
      end

      def regexp
        @regexp ||= /#{header}(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)/
      end

      # Standard header to search for
      def header
        @header ||= SymmetricEncryption.cipher.encoder.encode(SymmetricEncryption::MAGIC_HEADER).gsub('=', '')
      end

    end
  end
end
