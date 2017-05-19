module SymmetricEncryption
  module Keystore
    class Memory
      attr_accessor :key_encryption_key, :encoding
      attr_reader :encrypted_key

      # Stores the Encryption key in a string.
      # Secures the Encryption key by encrypting it with a key encryption key.
      def initialize(key_encryption_key:, encrypted_key: nil, encoding: :base64strict)
        @encrypted_key      = encrypted_key
        @key_encryption_key = key_encryption_key
        @encoding           = encoding
      end

      # Returns the Encryption key in the clear.
      def read
        binary = encoder.decode(encrypted_key)
        key_encryption_key.decrypt(binary)
      end

      # Write the encrypted Encryption key to `encrypted_key` attribute.
      def write(key)
        binary = key_encryption_key.encrypt(key)
        self.encrypted_key = encoder.encode(binary)
      end

      def encoder
        @encoder ||= SymmetricEncryption::Encoder[encoding]
      end
    end
  end
end
