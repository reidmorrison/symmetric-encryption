module SymmetricEncryption
  class Config
    attr_reader :file_name, :env

    # Load the Encryption Configuration from a YAML file.
    #
    #  file_name:
    #    Name of configuration file.
    #    Default: "#{Rails.root}/config/symmetric-encryption.yml"
    #    Note:
    #      The Symmetric Encryption config file name can also be set using the `SYMMETRIC_ENCRYPTION_CONFIG`
    #      environment variable.
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
        file_name =
          if env_var = ENV['SYMMETRIC_ENCRYPTION_CONFIG']
            File.expand_path(env_var)
          else
            File.join(root, 'config', 'symmetric-encryption.yml')
          end
        raise(ConfigError, "Cannot find config file: #{file_name}") unless File.exist?(file_name)
      end

      @env       = env
      @file_name = file_name
    end

    # Returns [Hash] the configuration for the supplied environment.
    def config
      @config ||= begin
        raise(ConfigError, "Cannot find config file: #{file_name}") unless File.exist?(file_name)
        cfg    = YAML.load(ERB.new(File.new(file_name).read).result)[env]
        cfg = self.class.deep_symbolize_keys(cfg)
        migrate_old_formats(cfg)
      end
    end

    # Returns [Array(SymmetricEncrytion::Cipher)] ciphers specified in the configuration file.
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

    # Iterate through the Hash symbolizing all keys.
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

    # Iterate through the Hash symbolizing all keys.
    def self.deep_stringify_keys(x)
      case x
      when Hash
        result = {}
        x.each_pair do |key, value|
          key         = key.to_s if key.is_a?(Symbol)
          result[key] = deep_stringify_keys(value)
        end
        result
      when Array
        x.collect { |i| deep_stringify_keys(i) }
      else
        x
      end
    end

    def migrate_old_formats(config)
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

  end
end
