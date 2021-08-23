module SymmetricEncryption
  module Encoder
    def self.[](encoding)
      case encoding
      when :base64
        Base64.new
      when :base64strict
        Base64Strict.new
      when :base64urlsafe
        Base64UrlSafe.new
      when :base16
        Base16.new
      when :none
        None.new
      else
        raise(ArgumentError, "Unknown encoder: #{encoding.inspect}")
      end
    end

    def self.encode(binary_string, encoding)
      encoder(encoding).encode(binary_string)
    end

    def self.decode(encoded_string, encoding)
      encoder(encoding).decode(encoded_string)
    end

    class None
      def encode(binary_string)
        binary_string&.dup
      end

      def decode(encoded_string)
        encoded_string&.dup
      end
    end

    class Base64
      def encode(binary_string)
        return binary_string if binary_string.nil? || (binary_string == "")

        encoded_string = ::Base64.encode64(binary_string)
        encoded_string.force_encoding(SymmetricEncryption::UTF8_ENCODING)
      end

      def decode(encoded_string)
        return encoded_string if encoded_string.nil? || (encoded_string == "")

        decoded_string = ::Base64.decode64(encoded_string)
        decoded_string.force_encoding(SymmetricEncryption::BINARY_ENCODING)
      end
    end

    class Base64Strict
      def encode(binary_string)
        return binary_string if binary_string.nil? || (binary_string == "")

        encoded_string = ::Base64.strict_encode64(binary_string)
        encoded_string.force_encoding(SymmetricEncryption::UTF8_ENCODING)
      end

      def decode(encoded_string)
        return encoded_string if encoded_string.nil? || (encoded_string == "")

        decoded_string = ::Base64.decode64(encoded_string)
        decoded_string.force_encoding(SymmetricEncryption::BINARY_ENCODING)
      end
    end

    class Base64UrlSafe
      def encode(binary_string)
        return binary_string if binary_string.nil? || (binary_string == "")

        encoded_string = ::Base64.urlsafe_encode64(binary_string)
        encoded_string.force_encoding(SymmetricEncryption::UTF8_ENCODING)
      end

      def decode(encoded_string)
        return encoded_string if encoded_string.nil? || (encoded_string == "")

        decoded_string = ::Base64.urlsafe_decode64(encoded_string)
        decoded_string.force_encoding(SymmetricEncryption::BINARY_ENCODING)
      end
    end

    class Base16
      def encode(binary_string)
        return binary_string if binary_string.nil? || (binary_string == "")

        encoded_string = binary_string.to_s.unpack("H*").first
        encoded_string.force_encoding(SymmetricEncryption::UTF8_ENCODING)
      end

      def decode(encoded_string)
        return encoded_string if encoded_string.nil? || (encoded_string == "")

        decoded_string = [encoded_string].pack("H*")
        decoded_string.force_encoding(SymmetricEncryption::BINARY_ENCODING)
      end
    end
  end
end
