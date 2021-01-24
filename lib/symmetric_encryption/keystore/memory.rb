module SymmetricEncryption
  module Keystore
    # In Memory Keystore usually used for testing purposes
    class Memory
      attr_accessor :key_encrypting_key
      attr_reader :encrypted_key

      # Returns [Hash] a new keystore configuration after generating the data key.
      #
      # Increments the supplied version number by 1.
      #
      # Notes:
      # * For development and testing purposes only!!
      # * Never store the encrypted encryption key in the source code / config file.
      def self.generate_data_key(cipher_name:, app_name:, environment:, version: 0, dek: nil, **_args)
        version >= 255 ? (version = 1) : (version += 1)

        kek = SymmetricEncryption::Key.new(cipher_name: cipher_name)
        dek ||= SymmetricEncryption::Key.new(cipher_name: cipher_name)

        encrypted_key = new(key_encrypting_key: kek).write(dek.key)

        {
          keystore:           :memory,
          cipher_name:        cipher_name,
          version:            version,
          encrypted_key:      encrypted_key,
          iv:                 iv,
          key_encrypting_key: {
            key: kek.key,
            iv:  kek.iv
          }
        }
      end

      # Stores the Encryption key in a string.
      # Secures the Encryption key by encrypting it with a key encryption key.
      def initialize(key_encrypting_key:, encrypted_key: nil)
        @encrypted_key      = encrypted_key
        @key_encrypting_key = key_encrypting_key
      end

      # Returns the Encryption key in the clear.
      def read
        key_encrypting_key.decrypt(encrypted_key)
      end

      # Write the encrypted Encryption key to `encrypted_key` attribute.
      def write(key)
        self.encrypted_key = key_encrypting_key.encrypt(key)
      end
    end
  end
end
