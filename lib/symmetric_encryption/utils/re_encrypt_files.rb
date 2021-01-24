# Used for re-encrypting encrypted passwords stored in configuration files.
#
# Search for any encrypted value and re-encrypt it using the latest encryption key.
# Note:
# * Only works with encrypted values that have the standard header.
#   * The search looks for the header and then replaces the encrypted value.
#
# Example:
#   re_encrypt = SymmetricEncryption::Utils::ReEncryptFiles.new(version: 4)
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
    #   A file that is already encrypted with the specified key version is not re-encrypted.
    #   If an encrypted value cannot be decypted in the current environment it is left unmodified.
    #
    #   If a file is not encrypted, the file is searched for any encrypted values, and those values are re-encrypted.
    #
    #   symmetric_encryption --reencrypt "**/*.yml"
    class ReEncryptFiles
      attr_accessor :cipher, :version

      # Parameters:
      #   version: [Integer]
      #     Version of the encryption key to use when re-encrypting the value.
      #     Default: Default cipher ( first in the list of configured ciphers )
      def initialize(version: SymmetricEncryption.cipher.version)
        @version = version || SymmetricEncryption.cipher.version
        @cipher  = SymmetricEncryption.cipher(@version)
        raise(ArgumentError, "Undefined encryption key version: #{version}") if @cipher.nil?
      end

      # Re-encrypt the supplied encrypted value with the new cipher
      def re_encrypt(encrypted)
        if (unencrypted = SymmetricEncryption.try_decrypt(encrypted))
          cipher.encrypt(unencrypted)
        else
          encrypted
        end
      end

      # Process a single file.
      #
      # Returns [Integer] number of encrypted values re-encrypted.
      def re_encrypt_contents(file_name)
        return 0 if File.size(file_name) > 256 * 1024

        lines              = File.read(file_name)
        hits, output_lines = re_encrypt_lines(lines)

        File.open(file_name, "wb") { |file| file.write(output_lines) } if hits.positive?
        hits
      end

      # Replaces instances of encrypted data within lines of text with re-encrypted values
      def re_encrypt_lines(lines)
        hits         = 0
        output_lines = ""
        r            = regexp
        lines.each_line do |line|
          line.force_encoding(SymmetricEncryption::UTF8_ENCODING)
          output_lines <<
            if line.valid_encoding? && (result = line.match(r))
              encrypted = result[0]
              new_value = re_encrypt(encrypted)
              if new_value == encrypted
                line
              else
                hits += 1
                line.gsub(encrypted, new_value)
              end
            else
              line
            end
        end
        [hits, output_lines]
      end

      # Re Encrypt an entire file
      def re_encrypt_file(file_name)
        temp_file_name = "__re_encrypting_#{file_name}"
        SymmetricEncryption::Reader.open(file_name) do |source|
          SymmetricEncryption::Writer.encrypt(source: source, target: temp_file_name, compress: true, version: version)
        end
        File.delete(file_name)
        File.rename(temp_file_name, file_name)
      rescue StandardError
        File.delete(temp_file_name) if temp_file_name && File.exist?(temp_file_name)
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
          next if File.directory?(file_name)

          if (v = encrypted_file_version(file_name))
            if v == version
              puts "Skipping already re-encrypted file: #{file_name}"
            else
              puts "Re-encrypting entire file: #{file_name}"
              re_encrypt_file(file_name)
            end
          else
            begin
              count = re_encrypt_contents(file_name)
              puts "Re-encrypted #{count} encrypted value(s) in: #{file_name}" if count.positive?
            rescue StandardError => e
              puts "Failed re-encrypting the file contents of: #{file_name}. #{e.class.name}: #{e.message}"
            end
          end
        end
      end

      private

      def regexp
        @regexp ||= %r{#{SymmetricEncryption.cipher.encoded_magic_header}([A-Za-z0-9+/]+[=\\n]*)}
      end

      # Returns [Integer] encrypted file key version.
      # Returns [nil] if the file is not encrypted or does not have a header.
      def encrypted_file_version(file_name)
        ::File.open(file_name, "rb") do |file|
          reader = SymmetricEncryption::Reader.new(file)
          reader.version if reader.header_present?
        end
      rescue OpenSSL::Cipher::CipherError
        nil
      end
    end
  end
end
