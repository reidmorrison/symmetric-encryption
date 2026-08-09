module SymmetricEncryption
  # Encryption keys are secured in Keystores
  module Keystore
    # @formatter:off
    autoload :Aws,         "symmetric_encryption/keystore/aws"
    autoload :Environment, "symmetric_encryption/keystore/environment"
    autoload :Gcp,         "symmetric_encryption/keystore/gcp"
    autoload :File,        "symmetric_encryption/keystore/file"
    autoload :Heroku,      "symmetric_encryption/keystore/heroku"
    autoload :Memory,      "symmetric_encryption/keystore/memory"
    # @formatter:on

    # Returns [Hash] a new keystore configuration after generating data keys for each environment.
    def self.generate_data_keys(keystore:, environments: %i[development test release production], **args)
      keystore_class = keystore.is_a?(Symbol) || keystore.is_a?(String) ? constantize_symbol(keystore) : keystore

      configs = {}
      environments.each do |environment|
        environment          = environment.to_sym
        configs[environment] =
          if %i[development test].include?(environment)
            dev_config
          else
            cfg = keystore_class.generate_data_key(environment: environment, **args)
            {
              ciphers: [cfg]
            }
          end
      end
      configs
    end

    # Returns [Hash] a new configuration file after performing key rotation.
    #
    # Perform key rotation for each of the environments in the configuration file, by
    # * generating a new key, and iv with an incremented version number.
    #
    # Params:
    #   full_config: [Hash]
    #     The current contents of `symmetric-encryption.yml`, every environment. Updated in place
    #     as well as returned.
    #
    #   app_name: [String]
    #     Application name, used to name the new key files or environment variables.
    #
    #   environments: [Array<Symbol>]
    #     List of environments to perform key rotation for.
    #     Default: All environments found in the current configuration file.
    #     Note: An environment that holds its key in the configuration file itself, which is how
    #       development and test are generated, is skipped either way. There is no keystore to
    #       generate a new key from.
    #
    #   rolling_deploy: [true|false]
    #     To support a rolling deploy of the new key it must added initially as the second key.
    #     Then in a subsequent deploy the key can be moved into the first position to activate it.
    #     In this way during a rolling deploy encrypted values written by updated servers will be readable
    #     by the servers that have not been updated yet.
    #     Default: false
    #
    #   keystore: [Symbol]
    #     If supplied, changes the keystore during key rotation.
    #
    #   key_path: [String]
    #     If supplied, writes the new key files to this path instead of alongside the current ones.
    #
    #   regions: [Array<String>]
    #     AWS KMS only. If supplied, encrypts the new data key with the master key in these regions
    #     instead of the regions the current key files cover.
    #
    # Notes:
    # * iv_filename is no longer supported and is removed when creating a new random cipher.
    #     * `iv` does not need to be encrypted and is included in the clear.
    def self.rotate_keys!(full_config, app_name:, environments: [], rolling_deploy: false, keystore: nil,
                          key_path: nil, regions: nil)
      full_config.each_pair do |environment, cfg|
        # Only rotate keys for specified environments. Default, all
        next if !environments.empty? && !environments.include?(environment.to_sym)

        # Find the highest version number
        version = cfg[:ciphers].collect { |c| c[:version] || 0 }.max

        config = cfg[:ciphers].first

        # Development and test hold their key in the config file itself, so there is no keystore
        # to generate a new key from.
        next if config[:key]

        cipher_name = config[:cipher_name] || "aes-256-cbc"

        current_keystore_class = keystore_for(config)
        keystore_class         = keystore ? constantize_symbol(keystore) : current_keystore_class

        args = {
          cipher_name: cipher_name,
          app_name:    app_name,
          version:     version,
          environment: environment
        }
        # Where the current keys live, so that the new keys are written alongside them. Read from
        # the keystore the config describes, which is still the source when migrating to another.
        args.merge!(current_keystore_class.rotate_args(config))
        # Supplied values win, since they are how the destination is changed.
        args[:key_path] = key_path if key_path
        args[:regions]  = regions if regions && !regions.empty?
        # Carry over what the current key files are expected to look like, otherwise the rewritten
        # config no longer describes the key files it names.
        %i[permissions owner group].each { |name| args[name] = config[name] if config.key?(name) }
        new_data_key = keystore_class.generate_data_key(**args)

        # Add as second key so that key can be published now and only used in a later deploy.
        if rolling_deploy
          cfg[:ciphers].insert(1, new_data_key)
        else
          cfg[:ciphers].unshift(new_data_key)
        end
      end
      full_config
    end

    # Rotates just the key encrypting keys for the current cipher version.
    # The existing data encryption key is not changed, it is secured using the
    # new key encrypting keys.
    #
    # Returns [Hash] the configuration, updated in place as well as returned.
    #
    # Params: as for `.rotate_keys!`.
    #
    # Note: Only the keystores that hold the key encrypting key in the configuration file can be
    #   rotated here. AWS KMS and GCP Cloud KMS hold the master key themselves, where it is
    #   rotated through their own management interface.
    def self.rotate_key_encrypting_keys!(full_config, app_name:, environments: [])
      full_config.each_pair do |environment, cfg|
        # Only rotate keys for specified environments. Default, all
        next if !environments.empty? && !environments.include?(environment.to_sym)

        config = cfg[:ciphers].first

        # Only the keystores that hold the key encrypting key in the config file can rotate it
        # here. AWS KMS and GCP Cloud KMS hold the master key themselves, where it is rotated
        # through their own management interface. Development and test hold the data encrypting
        # key in the config file in the clear, so there is nothing securing it to replace.
        next unless config[:key_encrypting_key]

        version = config.delete(:version) || 1
        version -= 1

        always_add_header = config.delete(:always_add_header)
        encoding          = config.delete(:encoding)

        migrate_config!(config)

        # The current data encrypting key without any of the key encrypting keys.
        key            = Keystore.read_key(**config)
        cipher_name    = key.cipher_name
        keystore_class = keystore_for(config)

        args = {
          cipher_name: cipher_name,
          app_name:    app_name,
          version:     version,
          environment: environment,
          dek:         key
        }
        # Where the current keys live, so that the new keys are written alongside them.
        args.merge!(keystore_class.rotate_args(config))
        # Carry over what the current key files are expected to look like, otherwise the rewritten
        # config no longer describes the key files it names.
        %i[permissions owner group].each { |name| args[name] = config[name] if config.key?(name) }

        new_config                     = keystore_class.generate_data_key(**args)
        # Only carry over these settings when they were set explicitly, otherwise the
        # rewritten config file overrides the defaults with nil.
        new_config[:always_add_header] = always_add_header unless always_add_header.nil?
        new_config[:encoding]          = encoding unless encoding.nil?

        # Replace existing config entry
        cfg[:ciphers].shift
        cfg[:ciphers].unshift(new_config)
      end
      full_config
    end

    # The default development config.
    def self.dev_config
      {
        ciphers:
                 [
                   {
                     key:         "1234567890ABCDEF",
                     iv:          "1234567890ABCDEF",
                     cipher_name: "aes-128-cbc",
                     version:     1
                   }
                 ]
      }
    end

    # Returns [Key] by recursively navigating the config tree.
    #
    # Supports N level deep key encrypting keys.
    # `version` is named only to keep it out of `args`, which is passed on to the keystore.
    # rubocop:disable Lint/UnusedMethodArgument
    def self.read_key(iv:, key: nil, key_encrypting_key: nil, cipher_name: "aes-256-cbc", keystore: nil, version: 0, **args)
      # rubocop:enable Lint/UnusedMethodArgument
      if key_encrypting_key.is_a?(Hash)
        # Recurse up the chain returning the parent key_encrypting_key
        key_encrypting_key = read_key(cipher_name: cipher_name, **key_encrypting_key)
      end

      unless key
        keystore_class = keystore ? constantize_symbol(keystore) : keystore_for(args)
        store          = keystore_class.new(key_encrypting_key: key_encrypting_key, **args)
        key            = store.read
      end

      Key.new(key: key, iv: iv, cipher_name: cipher_name)
    end

    #
    # Internal use only methods
    #

    def self.keystore_for(config)
      if config[:keystore]
        constantize_symbol(config[:keystore])
      elsif config[:encrypted_key]
        Keystore::Memory
      elsif config[:key_filename]
        Keystore::File
      elsif config[:key_env_var]
        Keystore::Environment
      else
        raise(ArgumentError, "Unknown keystore supplied in config")
      end
    end

    def self.constantize_symbol(symbol, namespace = "SymmetricEncryption::Keystore")
      klass = "#{namespace}::#{camelize(symbol.to_s)}"
      begin
        Object.const_get(klass)
      rescue NameError
        raise(ArgumentError, "Keystore: #{symbol.inspect} not found. Looking for: #{klass}")
      end
    end

    # Borrow from Rails, when not running Rails
    def self.camelize(term)
      string = term.to_s
      string = string.sub(/^[a-z\d]*/, &:capitalize)
      string.gsub!(%r{(?:_|(/))([a-z\d]*)}i) { "#{Regexp.last_match(1)}#{Regexp.last_match(2).capitalize}" }
      string.gsub!("/".freeze, "::".freeze)
      string
    end

    # Migrate a prior config.
    #
    # Note:
    # * The config cannot be saved back to the config file once
    #   migrated, without generating new Key Encrypting Keys.
    # * Only run this migration in the target environment so that the
    #   current key encrypting files are present.
    def self.migrate_config!(config)
      # Backward compatibility - Deprecated
      private_rsa_key = config.delete(:private_rsa_key)

      # Migrate old encrypted_iv
      if (encrypted_iv = config.delete(:encrypted_iv)) && private_rsa_key
        config[:iv] = RSAKey.new(private_rsa_key).decrypt(::Base64.decode64(encrypted_iv))
      end

      # Migrate old iv_filename
      if (file_name = config.delete(:iv_filename)) && private_rsa_key
        encrypted_iv = ::File.read(file_name)
        config[:iv]  = RSAKey.new(private_rsa_key).decrypt(encrypted_iv)
      end

      # Backward compatibility - Deprecated
      config[:key_encrypting_key] = RSAKey.new(private_rsa_key) if private_rsa_key

      # Migrate old encrypted_key to new binary format
      return unless (encrypted_key = config[:encrypted_key]) && private_rsa_key

      config[:encrypted_key] = ::Base64.decode64(encrypted_key)
    end
  end
end
