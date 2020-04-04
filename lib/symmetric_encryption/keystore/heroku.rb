module SymmetricEncryption
  module Keystore
    # Heroku uses environment variables too.
    class Heroku < Environment
      # Returns [Hash] a new keystore configuration after generating the data key.
      def self.generate_data_key(**args)
        config            = super(**args)
        config[:keystore] = :heroku
        config
      end

      # Write the encrypted Encryption key to `encrypted_key` attribute.
      def write(key)
        encrypted_key = key_encrypting_key.encrypt(key)
        puts "\n\n********************************************************************************"
        puts "Add the environment key to Heroku:\n\n"
        puts "  heroku config:add #{key_env_var}=#{encoder.encode(encrypted_key)}"
        puts "********************************************************************************"
      end
    end
  end
end
