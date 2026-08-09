module SymmetricEncryption
  module Keystore
    # Heroku uses environment variables too.
    class Heroku < Environment
      # Returns [Hash] a new keystore configuration after generating the data key.
      def self.generate_data_key(**args)
        config            = super
        config[:keystore] = :heroku
        config
      end

      # Encrypts the Encryption key and prints the `heroku config:add` command that sets it.
      #
      # Nothing is written anywhere, running that command is left to whoever is deploying.
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
