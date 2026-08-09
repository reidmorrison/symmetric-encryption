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

      # Reads the Encryption key from an environment var.
      # The Encryption key is secured by encrypting it with a key encryption key.
      #
      # encoding: [Symbol]
      #   How the encrypted key is encoded in the environment variable, since an environment
      #   variable holds text rather than binary data. See `SymmetricEncryption::Encoder`.
      #   Default: :base64strict
      def initialize(key_encrypting_key:, key_env_var:, encoding: :base64strict)
        # Memory holds the encrypted key in an attribute. Here it lives in the environment
        # variable instead, so there is nothing to hand up.
        super(key_encrypting_key: key_encrypting_key)
        @key_env_var = key_env_var
        @encoding    = encoding
      end

      # Returns the Encryption key in the clear.
      def read
        encrypted = ENV.fetch(key_env_var, nil)
        raise "The Environment Variable #{key_env_var} must be set with the encrypted encryption key." unless encrypted

        binary = encoder.decode(encrypted)
        key_encrypting_key.decrypt(binary)
      end

      # Encrypts the Encryption key and prints how to set the environment variable that holds it.
      #
      # Nothing is written anywhere. Setting the environment variable is the deploy's job, which
      # is the point of this keystore: the encrypted key never lands in the config file.
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
