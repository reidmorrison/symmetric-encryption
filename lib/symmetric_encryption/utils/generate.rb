module SymmetricEncryption
  module Utils
    class Generate
      # Generate a new config file
      # Returns the name of the new configuration file
      def self.config(heroku: false,
                 key_path: '/etc/symmetric-encryption',
                 app_name: 'symmetric-encryption',
                 filename: 'config/symmetric-encryption.yml')

        # key_path and app_name are used in the template
        template      = heroku ? 'heroku_config/templates' : 'config/templates'
        template_path = File.expand_path("../../rails/generators/symmetric_encryption/#{template}", __FILE__)
        data          = File.read(template_path)

        File.open(filename, 'w') do |f|
          f << ERB.new(data, nil, '-').result(binding)
        end

        filename
      end

      # Generate new random symmetric keys for use with this Encryption library
      #
      # Note: Only the current Encryption key settings are used
      #
      # Creates Symmetric Key .key and initialization vector .iv
      # which is encrypted with the key encryption key.
      #
      # Existing key files will be renamed if present
      def self.key_files(filename: nil, environment: nil)
        config = Config.read_config(filename, environment)

        # Only regenerating the first configured cipher
        cipher_config = config[:ciphers].first

        # Delete unused config keys to generate new random keys
        [:version, :always_add_header].each do |key|
          cipher_config.delete(key)
        end

        key_config = {private_rsa_key: config[:private_rsa_key]}
        cipher_cfg = Cipher.generate_random_keys(key_config.merge(cipher_config))

        puts
        if encoded_encrypted_key = cipher_cfg[:encrypted_key]
          puts 'If running in Heroku, add the environment specific key:'
          puts "heroku config:add #{environment.upcase}_KEY1=#{encoded_encrypted_key}\n"
        end

        if encoded_encrypted_iv = cipher_cfg[:encrypted_iv]
          puts 'If running in Heroku, add the environment specific key:'
          puts "heroku config:add #{environment.upcase}_IV1=#{encoded_encrypted_iv}"
        end

        if key = cipher_cfg[:key]
          puts "Please add the key: #{key} to your config file"
        end

        if iv = cipher_cfg[:iv]
          puts "Please add the iv: #{iv} to your config file"
        end

        if file_name = cipher_cfg[:key_filename]
          puts("Please copy #{file_name} to the other servers in #{environment}.")
        end

        if file_name = cipher_cfg[:iv_filename]
          puts("Please copy #{file_name} to the other servers in #{environment}.")
        end
        cipher_cfg
      end

    end
  end
end
