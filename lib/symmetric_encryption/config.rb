module SymmetricEncryption
  class Config
    attr_reader :file_name, :env

    # Load the Encryption Configuration from a YAML file
    #  file_name:
    #    Name of configuration file.
    #    Default: "#{Rails.root}/config/symmetric-encryption.yml"
    #
    #  env:
    #    Which environments config to load. Usually: production, development, etc.
    #    Non-Rails apps can set env vars: RAILS_ENV, or RACK_ENV
    #    Default: Rails.env || ENV['RACK_ENV'] || ENV['RAILS_ENV'] || 'development'
    def self.load!(file_name: nil, env: nil)
      config                                = new(file_name: file_name, env: env)
      ciphers                               = config.ciphers
      SymmetricEncryption.cipher            = ciphers.shift
      SymmetricEncryption.secondary_ciphers = ciphers
      true
    end

    # Load the Encryption Configuration from a YAML file.
    #
    # See: `.load!` for parameters.
    def initialize(file_name: nil, env: nil)
      unless env
        env = defined?(Rails) ? Rails.env : ENV['RACK_ENV'] || ENV['RAILS_ENV'] || 'development'
      end

      unless file_name
        root      = defined?(Rails) ? Rails.root : '.'
        file_name = File.join(root, 'config', 'symmetric-encryption.yml')
        raise(ConfigError, "Cannot find config file: #{file_name}") unless File.exist?(file_name)
      end

      @env       = env
      @file_name = file_name
    end

    # Returns [Hash] the configuration for the supplied environment
    def config
      @config ||= begin
        cfg = YAML.load(ERB.new(File.new(file_name).read).result)[env]
        deep_symbolize_keys(cfg)
      end
    end

    # Returns [Array(SymmetricEncrytion::Cipher)] ciphers specified in the configuration file
    #
    # Read the configuration from the YAML file and return in the latest format
    #
    #  file_name:
    #    Name of file to read.
    #        Mandatory for non-Rails apps
    #        Default: Rails.root/config/symmetric-encryption.yml
    #  env:
    #    Which environments config to load. Usually: production, development, etc.
    def ciphers
      @ciphers ||= begin
        private_rsa_key = config[:private_rsa_key]
        ciphers         = config[:ciphers]
        raise(SymmetricEncryption::ConfigError, 'Missing required :ciphers') unless ciphers

        ciphers.collect do |cipher_config|
          Cipher.new({private_rsa_key: private_rsa_key}.merge(cipher_config))
        end
      end
    end

    private

    # Iterate through the Hash symbolizing all keys
    def deep_symbolize_keys(x)
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
