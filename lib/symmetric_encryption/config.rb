require "erb"
require "yaml"
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

    # Reads the entire configuration for all environments from the supplied file name.
    def self.read_file(file_name)
      config = YAML.load(ERB.new(File.new(file_name).read).result, aliases: true)
      config = deep_symbolize_keys(config)
      config.each_pair { |_env, cfg| SymmetricEncryption::Config.send(:migrate_old_formats!, cfg) }
      config
    end

    # Write the entire configuration for all environments to the supplied file name.
    def self.write_file(file_name, config)
      config = deep_stringify_keys(config)

      FileUtils.mkdir_p(File.dirname(file_name))
      File.open(file_name, "w") do |f|
        f.puts "# This file was auto generated by symmetric-encryption."
        f.puts "# Recommend using symmetric-encryption to make changes."
        f.puts "# For more info, run:"
        f.puts "#   symmetric-encryption --help"
        f.puts "#"
        f.write(config.to_yaml)
      end
    end

    # Load the Encryption Configuration from a YAML file.
    #
    # See: `.load!` for parameters.
    def initialize(file_name: nil, env: nil)
      env ||= defined?(Rails) ? Rails.env : ENV["RACK_ENV"] || ENV["RAILS_ENV"] || "development"

      unless file_name
        root      = defined?(Rails) ? Rails.root : "."
        file_name =
          if (env_var = ENV["SYMMETRIC_ENCRYPTION_CONFIG"])
            File.expand_path(env_var)
          else
            File.join(root, "config", "symmetric-encryption.yml")
          end
        raise(ConfigError, "Cannot find config file: #{file_name}") unless File.exist?(file_name)
      end

      @env       = env
      @file_name = file_name
    end

    # Returns [Hash] the configuration for the supplied environment.
    def config
      @config ||=
        begin
          raise(ConfigError, "Cannot find config file: #{file_name}") unless File.exist?(file_name)

          env_config = YAML.load(ERB.new(File.new(file_name).read).result, aliases: true)[env]
          raise(ConfigError, "Cannot find environment: #{env} in config file: #{file_name}") unless env_config

          env_config = self.class.send(:deep_symbolize_keys, env_config)
          self.class.send(:migrate_old_formats!, env_config)
        end
    end

    # Returns [Array(SymmetricEncryption::Cipher)] ciphers specified in the configuration file.
    def ciphers
      @ciphers ||= config[:ciphers].collect { |cipher_config| Cipher.from_config(**cipher_config) }
    end

    # Iterate through the Hash symbolizing all keys.
    def self.deep_symbolize_keys(object)
      case object
      when Hash
        result = {}
        object.each_pair do |key, value|
          key         = key.to_sym if key.is_a?(String)
          result[key] = deep_symbolize_keys(value)
        end
        result
      when Array
        object.collect { |i| deep_symbolize_keys(i) }
      else
        object
      end
    end

    private_class_method :deep_symbolize_keys

    # Iterate through the Hash symbolizing all keys.
    def self.deep_stringify_keys(object)
      case object
      when Hash
        result = {}
        object.each_pair do |key, value|
          key         = key.to_s if key.is_a?(Symbol)
          result[key] = deep_stringify_keys(value)
        end
        result
      when Array
        object.collect { |i| deep_stringify_keys(i) }
      else
        object
      end
    end

    private_class_method :deep_stringify_keys

    # Migrate old configuration format for this environment
    def self.migrate_old_formats!(config)
      # Inline single cipher before :ciphers
      unless config.key?(:ciphers)
        inline_cipher = {}
        config.keys.each { |key| inline_cipher[key] = config.delete(key) }
        config[:ciphers] = [inline_cipher]
      end

      # Copy Old :private_rsa_key into each ciphers config
      # Cipher.from_config replaces it with the RSA Kek
      if config[:private_rsa_key]
        private_rsa_key = config.delete(:private_rsa_key)
        config[:ciphers].each { |cipher| cipher[:private_rsa_key] = private_rsa_key }
      end

      # Old :cipher_name
      config[:ciphers].each do |cipher|
        if (old_key_name_cipher = cipher.delete(:cipher))
          cipher[:cipher_name] = old_key_name_cipher
        end

        # Only temporarily used during v4 Beta process
        cipher[:private_rsa_key] = cipher.delete(:key_encrypting_key) if cipher[:key_encrypting_key].is_a?(String)

        # Check for a prior env var in encrypted key
        # Example:
        #   encrypted_key: <%= ENV['VAR'] %>
        if cipher.key?(:encrypted_key) && cipher[:encrypted_key].nil?
          cipher[:key_env_var] = :placeholder
          puts "WARNING: :encrypted_key resolved to nil. Please see the migrated config file for the new option :key_env_var."
        end
      end
      config
    end

    private_class_method :migrate_old_formats!
  end
end
