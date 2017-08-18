module SymmetricEncryption
  module Keystore
    # Store the encrypted encryption key in an environment variable
    class Environment < Memory
      attr_accessor :key_env_var, :encoding

      # Returns [Hash] initial configuration for heroku.
      # Displays the keys that need to be added to the heroku environment.
      def self.new_config(app_name: 'symmetric-encryption',
        environments: %i(development test release production),
        cipher_name: 'aes-256-cbc')

        configs = {}
        environments.each do |environment|
          environment          = environment.to_sym
          configs[environment] =
            if %i(development test).include?(environment)
              Keystore.dev_config
            else
              cfg = new_key_config(cipher_name: cipher_name, app_name: app_name, environment: environment)
              {
                ciphers: [cfg]
              }
            end
        end
        configs
      end

      # Returns [Hash] a new cipher, and writes its encrypted key file.
      #
      # Increments the supplied version number by 1.
      def self.new_key_config(cipher_name:, app_name:, environment:, version: 0, dek: nil)
        version >= 255 ? (version = 1) : (version += 1)

        kek = SymmetricEncryption::Key.new(cipher_name: cipher_name)
        dek ||= SymmetricEncryption::Key.new(cipher_name: cipher_name)

        key_env_var = "#{app_name}_#{environment}_v#{version}".upcase.gsub('-', '_')
        new(key_env_var: key_env_var, key_encrypting_key: kek).write(dek.key)

        {
          cipher_name:        dek.cipher_name,
          version:            version,
          key_env_var:        key_env_var,
          iv:                 dek.iv,
          key_encrypting_key: {
            key: kek.key,
            iv:  kek.iv,
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
        puts "Add the environment key to Heroku:\n\n"
        puts "  heroku config:add #{key_env_var}=#{encoder.encode(encrypted_key)}"
        puts
        puts "Or, if using environment variables on another system set the environment variable as follows:\n\n"
        puts "  export #{key_env_var}=\"#{encoder.encode(encrypted_key)}\"\n\n"
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
