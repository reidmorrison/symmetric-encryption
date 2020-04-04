module SymmetricEncryption
  module Keystore
    # Store the encrypted encryption key in an environment variable
    class Environment < Memory
      attr_accessor :key_env_var, :encoding

      # Returns [Hash] a new keystore configuration after generating the data key.
      #
      # Increments the supplied version number by 1.
      def self.generate_data_key(cipher_name:, app_name:, environment:, version: 0, dek: nil, **_args)
        version >= 255 ? (version = 1) : (version += 1)

        kek = SymmetricEncryption::Key.new(cipher_name: cipher_name)
        dek ||= SymmetricEncryption::Key.new(cipher_name: cipher_name)

        key_env_var = "#{app_name}_#{environment}_v#{version}".upcase.tr("-", "_")
        new(key_env_var: key_env_var, key_encrypting_key: kek).write(dek.key)

        {
          keystore:           :environment,
          cipher_name:        dek.cipher_name,
          version:            version,
          key_env_var:        key_env_var,
          iv:                 dek.iv,
          key_encrypting_key: {
            key: kek.key,
            iv:  kek.iv
          }
        }
      end

      # Stores the Encryption key in an environment var.
      # Secures the Encryption key by encrypting it with a key encryption key.
      def initialize(key_encrypting_key:, key_env_var:, encoding: :base64strict)
        @key_env_var        = key_env_var
        @key_encrypting_key = key_encrypting_key
        @encoding           = encoding
      end

      # Returns the Encryption key in the clear.
      def read
        encrypted = ENV[key_env_var]
        raise "The Environment Variable #{key_env_var} must be set with the encrypted encryption key." unless encrypted

        binary = encoder.decode(encrypted)
        key_encrypting_key.decrypt(binary)
      end

      # Write the encrypted Encryption key to `encrypted_key` attribute.
      def write(key)
        encrypted_key = key_encrypting_key.encrypt(key)
        puts "\n\n********************************************************************************"
        puts "Set the environment variable as follows:"
        puts "  export #{key_env_var}=\"#{encoder.encode(encrypted_key)}\""
        puts "********************************************************************************"
      end

      private

      # Returns [SymmetricEncryption::Encoder] the encoder to use for the current encoding.
      def encoder
        @encoder ||= SymmetricEncryption::Encoder[encoding]
      end
    end
  end
end
