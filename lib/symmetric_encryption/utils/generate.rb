module SymmetricEncryption
  module Utils
    class Generate
      # Generate a new config file
      # Returns the name of the new configuration file
      def self.config(heroku: false,
        key_path: '/etc/symmetric-encryption',
        app_name: 'symmetric-encryption',
        file_name: 'config/symmetric-encryption.yml')

        # key_path and app_name are used in the template
        template      = heroku ? 'heroku_config/templates' : 'config/templates'
        template_path = File.expand_path("../../rails/generators/symmetric_encryption/#{template}", __FILE__)
        data          = File.read(template_path)

        File.open(file_name, 'w') do |f|
          f << ERB.new(data, nil, '-').result(binding)
        end

        file_name
      end

      # Generate new random symmetric keys for use with this Encryption library
      #
      # Note: Only the current Encryption key settings are used
      #
      # Creates Symmetric Key .key and initialization vector .iv
      # which is encrypted with the key encryption key.
      #
      # Existing key files will be renamed if present
      def self.key_files(file_name: nil, environment: nil)
        config = Config.read_config(file_name, environment)

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

      # Generate new randomized keys and generate key and iv files if supplied.
      # Overwrites key files for the current environment.
      #
      # Parameters
      #   :key_filename
      #     Name of file that will contain the symmetric key encrypted using the public
      #     key from the private_rsa_key.
      #  Or,
      #   :encrypted_key
      #     Symmetric key encrypted using the public key from the private_rsa_key
      #     and then Base64 encoded
      #
      #  Note:
      #    If :key_filename and :encrypted_key are not supplied then a new :key will be returned.
      #    :key is the Symmetric Key to use for encryption and decryption.
      #
      #
      #   :iv_filename
      #     Name of file containing symmetric key initialization vector
      #     encrypted using the public key from the private_rsa_key
      #     Deprecated: It is _not_ necessary to encrypt the initialization vector (IV)
      #  Or,
      #   :encrypted_iv
      #     Initialization vector encrypted using the public key from the private_rsa_key
      #     and then Base64 encoded
      #     Deprecated: It is _not_ necessary to encrypt the initialization vector (IV)
      #
      #  Note:
      #    If :iv_filename and :encrypted_iv are not supplied then a new :iv will be returned.
      #    :iv is the Initialization Vector to use with Symmetric Key.
      #
      #
      #   private_rsa_key [String]
      #     Key encryption key.
      #     To generate a new one: SymmetricEncryption::KeyEncryptionKey.generate
      #     Required if :key_filename, :encrypted_key, :iv_filename, or :encrypted_iv is supplied
      #
      #   :cipher_name [String]
      #     Encryption Cipher to use.
      #     Default: aes-256-cbc
      #
      #   :encoding [Symbol]
      #     :base64strict
      #       Return as a base64 encoded string that does not include additional newlines
      #       This is the recommended format since newlines in the values to
      #       SQL queries are cumbersome. Also the newline reformatting is unnecessary
      #       It is not the default for backward compatibility
      #     :base64
      #       Return as a base64 encoded string
      #     :base16
      #       Return as a Hex encoded string
      #     :none
      #       Return as raw binary data string. Note: String can contain embedded nulls
      #     Default: :base64strict
      def self.random_keys(cipher_name: 'aes-256-cbc', encoding: :base64strict,
        private_rsa_key: nil, key_filename: nil, iv_filename: nil)

        cipher = Cipher.new(
          cipher_name:     cipher_name,
          encoding:        encoding,
          private_rsa_key: private_rsa_key,
          key_filename:    key_filename,
          iv_filename:     iv_filename
        )
        cipher.to_h
      end

    end
  end
end
