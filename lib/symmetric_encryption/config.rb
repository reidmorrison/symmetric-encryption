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
      config = deep_symbolize_keys(config)

      # Old format?
      unless config.has_key?(:ciphers)
        config = {
          private_rsa_key: config.delete(:private_rsa_key),
          ciphers:         [config]
        }
      end

      # Old format cipher name?
      config[:ciphers] = config[:ciphers].collect do |cipher|
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
    def self.deep_symbolize_keys(x)
      case x
      when Hash
        result = {}
        x.each_pair do |key, value|
          key         = key.to_sym if key.is_a?(String)
          result[key] = deep_symbolize_keys(value)
        end
        result
      when Array
        x.collect { |i| deep_symbolize_keys(i) }
      else
        x
      end
    end

  end
end
