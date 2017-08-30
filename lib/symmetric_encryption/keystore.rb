module SymmetricEncryption
  module Keystore
    #@formatter:off
    autoload :Environment, 'symmetric_encryption/keystore/environment'
    autoload :File,        'symmetric_encryption/keystore/file'
    autoload :Memory,      'symmetric_encryption/keystore/memory'
    #@formatter:on

    # Returns [Hash] a new configuration file after performing key rotation.
    #
    # Perform key rotation for each of the environments in the configuration file, by
    # * generating a new key, and iv with an incremented version number.
    #
    # Params:
    #   config: [Hash]
    #     The current contents of `symmetric-encryption.yml`.
    #
    #   environments: [Array<String>]
    #     List of environments for which to perform key rotation for.
    #     Default: All environments found in the current configuration file except development and test.
    #
    #   rolling_deploy: [true|false]
    #     To support a rolling deploy of the new key it must added initially as the second key.
    #     Then in a subsequent deploy the key can be moved into the first position to activate it.
    #     In this way during a rolling deploy encrypted values written by updated servers will be readable
    #     by the servers that have not been updated yet.
    #     Default: false
    #
    # Notes:
    # * iv_filename is no longer supported and is removed when creating a new random cipher.
    #     * `iv` does not need to be encrypted and is included in the clear.
    def self.rotate_keys!(full_config, environments: [], app_name:, rolling_deploy: false)
      full_config.each_pair do |environment, cfg|
        # Only rotate keys for specified environments. Default, all
        next if !environments.empty? && !environments.include?(environment.to_sym)

        # Find the highest version number
        version = cfg[:ciphers].collect { |c| c[:version] || 0 }.max

        config = cfg[:ciphers].first

        # Only generate new keys for keystore's that have a key encrypting key
        next unless config[:key_encrypting_key] || config[:private_rsa_key]

        cipher_name    = config[:cipher_name] || 'aes-256-cbc'
        new_key_config =
          if config.has_key?(:key_filename)
            key_path = ::File.dirname(config[:key_filename])
            Keystore::File.new_key_config(key_path: key_path, cipher_name: cipher_name, app_name: app_name, version: version, environment: environment)
          elsif config.has_key?(:key_env_var)
            Keystore::Environment.new_key_config(cipher_name: cipher_name, app_name: app_name, version: version, environment: environment)
          elsif config.has_key?(:encrypted_key)
            Keystore::Memory.new_key_config(cipher_name: cipher_name, app_name: app_name, version: version, environment: environment)
          end

        # Add as second key so that key can be published now and only used in a later deploy.
        if rolling_deploy
          cfg[:ciphers].insert(1, new_key_config)
        else
          cfg[:ciphers].unshift(new_key_config)
        end
      end
      full_config
    end

    # Rotates just the key encrypting keys for the current cipher version.
    # The existing data encryption key is not changed, it is secured using the
    # new key encrypting keys.
    def self.rotate_key_encrypting_keys!(full_config, environments: [], app_name:)
      full_config.each_pair do |environment, cfg|
        # Only rotate keys for specified environments. Default, all
        next if !environments.empty? && !environments.include?(environment.to_sym)

        config = cfg[:ciphers].first

        # Only generate new keys for keystore's that have a key encrypting key
        next unless config[:key_encrypting_key]

        version = config.delete(:version) || 1
        version -= 1

        always_add_header = config.delete(:always_add_header)
        encoding          = config.delete(:encoding)

        Key.migrate_config!(config)

        # The current data encrypting key without any of the key encrypting keys.
        key            = Key.from_config(config)
        cipher_name    = key.cipher_name
        new_key_config =
          if config.has_key?(:key_filename)
            key_path = ::File.dirname(config[:key_filename])
            Keystore::File.new_key_config(key_path: key_path, cipher_name: cipher_name, app_name: app_name, version: version, environment: environment, dek: key)
          elsif config.has_key?(:key_env_var)
            Keystore::Environment.new_key_config(cipher_name: cipher_name, app_name: app_name, version: version, environment: environment, dek: key)
          elsif config.has_key?(:encrypted_key)
            Keystore::Memory.new_key_config(cipher_name: cipher_name, app_name: app_name, version: version, environment: environment, dek: key)
          end

        new_key_config[:always_add_header] = always_add_header
        new_key_config[:encoding]          = encoding

        # Replace existing config entry
        cfg[:ciphers].shift
        cfg[:ciphers].unshift(new_key_config)
      end
      full_config
    end

    # The default development config.
    def self.dev_config
      {
        ciphers:
          [
            {
              key:         '1234567890ABCDEF',
              iv:          '1234567890ABCDEF',
              cipher_name: 'aes-128-cbc',
              version:     1
            }
          ]
      }
    end

  end
end
