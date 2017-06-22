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
    def self.rotate_keys(config, environments: [], app_name:, rolling_deploy: false)
      config.each_pair do |environment, cfg|
        private_rsa_key = config[:private_rsa_key]
        next unless private_rsa_key

        # Only rotate keys for specified environments. Default, all
        next if !environments.empty? && environments.include?(environment)

        key_encryption_key = KeyEncryptionKey.new(private_rsa_key)

        # Migrate old format
        cfg                = {ciphers: [cfg]} unless cfg.has_key?(:ciphers)
        cipher_cfg         = cfg[:ciphers].first

        # Check for a prior env var in encrypted key
        # Example:
        #   encrypted_key: <%= ENV['VAR'] %>
        if cipher_cfg.has_key?(:encrypted_key) && cipher_cfg[:encrypted_key].nil?
          cipher_cfg[:key_env_var] = :placeholder
          puts "WARNING: The encrypted_key for #{environment} resolved to nil. Please see the generated config file for the new environment var name."
        end

        version     = cipher_cfg[:version] || 0
        cipher_name = cipher_cfg[:cipher_name] || 'aes-256-cbc'
        cfg         =
          if cipher_cfg.has_key?(:key_filename)
            key_path = File.dirname(cipher_cfg[:key_filename])
            Keystore::File.new_cipher(key_path: key_path, cipher_name: cipher_name, key_encryption_key: key_encryption_key, app_name: app_name, version: version, environment: environment)
          elsif cipher_cfg.has_key?(:key_env_var)
            Keystore::Environment.new_cipher(cipher_name: cipher_name, key_encryption_key: key_encryption_key, app_name: app_name, version: version, environment: environment)
          elsif cipher_cfg.has_key?(:encrypted_key)
            Keystore::Memory.new_cipher(cipher_name: cipher_name, key_encryption_key: key_encryption_key, app_name: app_name, version: version, environment: environment)
          end

        # Add as second key so that key can be published now and only used in a later deploy.
        if rolling_deploy
          cfg[:ciphers].insert(1, cfg)
        else
          cfg[:ciphers].prepend(cfg)
        end
      end
    end
  end
end
