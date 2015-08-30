module SymmetricEncryption
  module Config
    # Load the Encryption Configuration from a YAML file
    #  filename:
    #    Name of file to read.
    #        Mandatory for non-Rails apps
    #        Default: Rails.root/config/symmetric-encryption.yml
    #  environment:
    #    Which environments config to load. Usually: production, development, etc.
    #    Default: Rails.env
    def self.load!(filename=nil, environment=nil)
      config  = read_config(filename, environment)
      ciphers = extract_ciphers(config)

      SymmetricEncryption.cipher            = ciphers.shift
      SymmetricEncryption.secondary_ciphers = ciphers
      true
    end

    private

    # Returns [Hash] the configuration for the supplied environment
    def self.read_config(filename=nil, environment=nil)
      config_filename = filename || File.join(Rails.root, 'config', 'symmetric-encryption.yml')
      cfg             = YAML.load(ERB.new(File.new(config_filename).read).result)[environment || Rails.env]
      extract_config(cfg)
    end

    # Returns [ private_rsa_key, ciphers ] config
    def self.extract_config(config)
      config = symbolize_keys(config)

      # Old format?
      unless config.has_key?(:ciphers)
        config = {
          private_rsa_key: config.delete(:private_rsa_key),
          ciphers:         [config]
        }
      end

      # Old format cipher name?
      config[:ciphers] = config[:ciphers].collect do |cipher|
        cipher = symbolize_keys(cipher)
        if old_key_name_cipher = cipher.delete(:cipher)
          cipher[:cipher_name] = old_key_name_cipher
        end
        cipher
      end
      config
    end

    # Returns [Array(SymmetricEncrytion::Cipher)] ciphers specified in the configuration file
    #
    # Read the configuration from the YAML file and return in the latest format
    #
    #  filename:
    #    Name of file to read.
    #        Mandatory for non-Rails apps
    #        Default: Rails.root/config/symmetric-encryption.yml
    #  environment:
    #    Which environments config to load. Usually: production, development, etc.
    def self.extract_ciphers(config)
      # RSA key to decrypt key files
      private_rsa_key = config[:private_rsa_key]

      config[:ciphers].collect do |cipher_config|
        Cipher.new({private_rsa_key: private_rsa_key}.merge(cipher_config))
      end
    end

    # Iterate through the Hash symbolizing all keys
    def self.symbolize_keys(hash)
      h = {}
      hash.keys.each do |key|
        val           = hash[key]
        h[key.to_sym] =
          if val.respond_to?(:keys)
            deep_symbolize_keys(val)
          else
            h[key.to_sym] = val
          end
      end
      h
    end
  end
end
