# Used for re-encrypting encrypted passwords stored in configuration files.
#
# Search for `SymmetricEncryption.try_decrypt` in config files and replace the
# encrypted value with one encrypted using the new encryption key.
#
# Example:
#   re_encrypt = SymmetricEncryption::Utils::ReEncryptConfigFiles.new(version: 4)
#   re_encrypt.process_directory('../../**/*.yml')
module SymmetricEncryption
  module Utils
    class ReEncryptConfigFiles
      DEFAULT_REGEXP = /\A(.*)SymmetricEncryption.try_decrypt[\s\(\"\'].([\w@=+\/\\]+)[\'\"](.*)\Z/

      attr_accessor :cipher, :path, :search_regexp

      # Parameters:
      #   version: [Integer]
      #     Version of the encryption key to use when re-encrypting the value.
      #     Default: Default cipher ( first in the list of configured ciphers )
      def initialize(params={})
        params         = params.dup
        version        = params.delete(:version)
        @path          = params.delete(:path)
        @search_regexp = params.delete(:search_regexp) || DEFAULT_REGEXP
        @cipher        = SymmetricEncryption.cipher(version)
        raise(ArgumentError, "Undefined encryption key version: #{version}") if @cipher.nil?
        raise(ArgumentError, "Unknown parameters: #{params.inspect}") if params.size > 0
      end

      # Re-encrypt the supplied enctrypted value with the new cipher
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
      def process_file(file_name)
        match        = false
        lines        = File.read(file_name)
        output_lines = ''
        lines.each_line do |line|
          if result = line.match(search_regexp)
            before_str = result[1]
            encrypted  = result[2]
            after_str  = result[3]
            after_str  = after_str[1..-1] if after_str.starts_with?(')')
            new_value  = re_encrypt(encrypted)
            if new_value != encrypted
              match = true
              output_lines << "#{before_str}SymmetricEncryption.try_decrypt('#{new_value}')#{after_str}\n"
            else
              output_lines << line
            end
          else
            output_lines << line
          end
        end
        if match
          File.open(file_name, 'wb') { |file| file.write(output_lines) }
        end
        match
      end

      # Process a directory of files.
      #
      # Parameters:
      #   path: [String]
      #     Search path to look for files in.
      #     Example: '../../**/*.yml'
      def process_directory(path)
        Dir[path].each do |file_name|
          process_file(file_name)
        end
      end
    end
  end
end
