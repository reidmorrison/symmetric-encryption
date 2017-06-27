module SymmetricEncryption
  module Keystore
    class Memory
      attr_accessor :key_encryption_key, :encoding
      attr_reader :encrypted_key

      # Returns [Hash] a new cipher, and writes its encrypted key file.
      #
      # Increments the supplied version number by 1.
      #
      # Notes:
      # * For development and testing purposes only!!
      # * Never store the encryption key in the clear.
      # * Never store the encrypted encryption key in the source code / config file.
      def self.new_cipher(cipher_name:, key_encryption_key:, app_name:, environment:, version: 0)
        version >= 255 ? (version = 1) : (version += 1)

        cipher        = Cipher.new(cipher_name: cipher_name, key_encryption_key: key_encryption_key)
        encrypted_key = cipher.encrypted_key
        iv            = cipher.encoder.encode(cipher.iv)
        store         = new(key_encryption_key: key_encryption_key).write_encrypted(encrypted_key)
        {
          'encrypted_key' => store.read,
          'iv'            => iv,
          'cipher_name'   => cipher_name,
          'version'       => version
        }
      end

      # The default development config.
      def self.dev_config
        {
          'ciphers' =>
            [
              {
                'key'         => '1234567890ABCDEF',
                'iv'          => '1234567890ABCDEF',
                'cipher_name' => 'aes-128-cbc',
                'version'     => 1
              }
            ]
        }
      end

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
        binary             = key_encryption_key.encrypt(key)
        self.encrypted_key = encoder.encode(binary)
      end

      # Store an already encrypted key.
      def write_encrypted(encrypted_key)
        self.encrypted_key = encoder.encode(encrypted_key)
      end

      def encoder
        @encoder ||= SymmetricEncryption::Encoder[encoding]
      end
    end
  end
end
