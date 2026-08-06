require_relative "test_helper"

module SymmetricEncryption
  class KeystoreTest < Minitest::Test
    describe SymmetricEncryption::Keystore do
      let :keystore do
        SymmetricEncryption::Keystore::File.new(file_name: "tmp/tester.key", key_encrypting_key: SymmetricEncryption::Key.new)
      end

      let :the_test_path do
        path = "tmp/keystore_test"
        FileUtils.makedirs(path) unless ::File.exist?(path)
        path
      end

      after do
        # Cleanup generated encryption key files.
        `rm #{the_test_path}/* 2> /dev/null`
      end

      let :random_key do
        SymmetricEncryption::Key.new
      end

      let :stored_key do
        "1234567890ABCDEF1234567890ABCDEF"
      end

      let :stored_iv do
        "ABCDEF1234567890"
      end

      let :key do
        SymmetricEncryption::Key.new(key: stored_key, iv: stored_iv)
      end

      let :stored_key2 do
        "ABCDEF1234567890ABCDEF1234567890"
      end

      let :stored_iv2 do
        "1234567890ABCDEF"
      end

      let :key2 do
        SymmetricEncryption::Key.new(key: stored_key2, iv: stored_iv2)
      end

      let :stored_key3 do
        "ABCDEF0123456789ABCDEF0123456789"
      end

      let :stored_iv3 do
        "0123456789ABCDEF"
      end

      let :key3 do
        SymmetricEncryption::Key.new(key: stored_key3, iv: stored_iv3)
      end

      describe ".generate_data_keys" do
        let :environments do
          %i[development test acceptance preprod production]
        end

        let :config do
          SymmetricEncryption::Keystore.generate_data_keys(
            keystore:     :file,
            key_path:     the_test_path,
            app_name:     "tester",
            environments: environments,
            cipher_name:  "aes-128-cbc"
          )
        end

        it "creates keys for each environment" do
          assert_equal environments, config.keys, config
        end

        it "use test config for development and test" do
          assert_equal SymmetricEncryption::Keystore.dev_config, config[:test]
          assert_equal SymmetricEncryption::Keystore.dev_config, config[:development]
        end
      end

      describe ".rotate_keys" do
        let :environments do
          %i[development test acceptance preprod production]
        end

        let :config do
          SymmetricEncryption::Keystore.generate_data_keys(
            keystore:     :file,
            key_path:     the_test_path,
            app_name:     "tester",
            environments: environments,
            cipher_name:  "aes-128-cbc"
          )
        end

        let :rolling_deploy do
          false
        end

        let :key_rotation do
          SymmetricEncryption::Keystore.rotate_keys!(
            config,
            environments:   environments,
            app_name:       "tester",
            rolling_deploy: rolling_deploy
          )
        end

        it "creates an encrypted key file for all non-test environments" do
          (environments - %i[development test]).each do |env|
            assert key_rotation
            # The second argument is the failure message, not an expected value.
            assert key_rotation[env.to_sym], key_rotation.inspect # rubocop:disable Minitest/AssertWithExpectedArgument
            assert key_rotation[env.to_sym][:ciphers]
            assert ciphers = key_rotation[env.to_sym][:ciphers], "Environment #{env} is missing ciphers: #{key_rotation[env.to_sym].inspect}"
            assert_equal 2, ciphers.size, "Environment #{env}: #{ciphers.inspect}"
            assert new_config = ciphers.first
            assert file_name = new_config[:key_filename], "Environment #{env} is missing key_filename: #{ciphers.inspect}"
            assert_path_exists file_name
            assert_equal 2, new_config[:version]
          end
        end
      end

      describe ".rotate_key_encrypting_keys!" do
        let :environments do
          %i[development test preprod production]
        end

        let :config do
          SymmetricEncryption::Keystore.generate_data_keys(
            keystore:     :file,
            key_path:     the_test_path,
            app_name:     "tester",
            environments: environments,
            cipher_name:  "aes-128-cbc"
          )
        end

        it "retains the data encrypting key so that existing data is still readable" do
          before_config = Marshal.load(Marshal.dump(config[:production][:ciphers].first))
          before_key    = SymmetricEncryption::Keystore.read_key(**before_config)

          SymmetricEncryption::Keystore.rotate_key_encrypting_keys!(config, app_name: "tester", environments: environments)

          after_config = config[:production][:ciphers].first

          assert_equal before_key.key, SymmetricEncryption::Keystore.read_key(**after_config).key
        end

        it "replaces the key encrypting key" do
          before_kek = Marshal.load(Marshal.dump(config[:production][:ciphers].first[:key_encrypting_key]))

          SymmetricEncryption::Keystore.rotate_key_encrypting_keys!(config, app_name: "tester", environments: environments)

          refute_equal before_kek, config[:production][:ciphers].first[:key_encrypting_key]
        end

        it "does not add a new key version" do
          SymmetricEncryption::Keystore.rotate_key_encrypting_keys!(config, app_name: "tester", environments: environments)

          ciphers = config[:production][:ciphers]

          assert_equal 1, ciphers.size
          assert_equal 1, ciphers.first[:version]
        end

        it "does not override the encoding defaults when they were not set" do
          SymmetricEncryption::Keystore.rotate_key_encrypting_keys!(config, app_name: "tester", environments: environments)

          cipher = config[:production][:ciphers].first

          refute cipher.key?(:encoding), cipher.inspect
          refute cipher.key?(:always_add_header), cipher.inspect
        end

        it "retains explicit encoding settings" do
          config[:production][:ciphers].first[:encoding]          = :base64
          config[:production][:ciphers].first[:always_add_header] = false

          SymmetricEncryption::Keystore.rotate_key_encrypting_keys!(config, app_name: "tester", environments: environments)

          cipher = config[:production][:ciphers].first

          assert_equal :base64, cipher[:encoding]
          refute cipher[:always_add_header]
        end

        it "skips environments without a key encrypting key" do
          SymmetricEncryption::Keystore.rotate_key_encrypting_keys!(config, app_name: "tester", environments: environments)

          assert_equal SymmetricEncryption::Keystore.dev_config, config[:test]
        end
      end

      describe ".keystore_for" do
        it "uses the supplied keystore" do
          assert_equal SymmetricEncryption::Keystore::Heroku, SymmetricEncryption::Keystore.keystore_for(keystore: :heroku)
        end

        it "infers memory from an encrypted key" do
          assert_equal SymmetricEncryption::Keystore::Memory, SymmetricEncryption::Keystore.keystore_for(encrypted_key: "key")
        end

        it "infers file from a key file name" do
          assert_equal SymmetricEncryption::Keystore::File, SymmetricEncryption::Keystore.keystore_for(key_filename: "f.key")
        end

        it "infers environment from an env var name" do
          assert_equal SymmetricEncryption::Keystore::Environment, SymmetricEncryption::Keystore.keystore_for(key_env_var: "VAR")
        end

        it "raises when the keystore cannot be determined" do
          assert_raises(ArgumentError) { SymmetricEncryption::Keystore.keystore_for(iv: "1234567890ABCDEF") }
        end
      end

      describe ".constantize_symbol" do
        it "returns the keystore class" do
          assert_equal SymmetricEncryption::Keystore::File, SymmetricEncryption::Keystore.constantize_symbol(:file)
        end

        it "raises for an unknown keystore" do
          error = assert_raises(ArgumentError) { SymmetricEncryption::Keystore.constantize_symbol(:no_such_keystore) }
          assert_includes error.message, "not found"
        end
      end

      describe ".migrate_config!" do
        # The RSA key used by the test configuration file.
        let :private_rsa_key do
          file_name = File.join(File.dirname(__FILE__), "config", "symmetric-encryption.yml")
          SymmetricEncryption::Config.read_file(file_name)[:test][:ciphers].first[:private_rsa_key]
        end

        it "replaces the rsa key with a key encrypting key" do
          config = {private_rsa_key: private_rsa_key, encrypted_key: "key", iv: stored_iv}

          SymmetricEncryption::Keystore.migrate_config!(config)

          refute config.key?(:private_rsa_key)
          assert_kind_of SymmetricEncryption::RSAKey, config[:key_encrypting_key]
        end

        it "decrypts a prior encrypted_iv" do
          rsa_key = SymmetricEncryption::RSAKey.new(private_rsa_key)
          config  = {
            private_rsa_key: private_rsa_key,
            encrypted_iv:    ::Base64.encode64(rsa_key.encrypt(stored_iv))
          }

          SymmetricEncryption::Keystore.migrate_config!(config)

          assert_equal stored_iv, config[:iv]
          refute config.key?(:encrypted_iv)
        end

        it "decrypts a prior iv_filename" do
          rsa_key   = SymmetricEncryption::RSAKey.new(private_rsa_key)
          file_name = "#{the_test_path}/tester.iv"
          File.binwrite(file_name, rsa_key.encrypt(stored_iv))
          config = {private_rsa_key: private_rsa_key, iv_filename: file_name}

          SymmetricEncryption::Keystore.migrate_config!(config)

          assert_equal stored_iv, config[:iv]
          refute config.key?(:iv_filename)
        end

        it "decodes a prior base64 encrypted key" do
          config = {private_rsa_key: private_rsa_key, encrypted_key: ::Base64.encode64("encrypted"), iv: stored_iv}

          SymmetricEncryption::Keystore.migrate_config!(config)

          assert_equal "encrypted", config[:encrypted_key]
        end

        it "leaves a current config unchanged" do
          config = {key_filename: "tester.key", iv: stored_iv}

          SymmetricEncryption::Keystore.migrate_config!(config)

          assert_equal({key_filename: "tester.key", iv: stored_iv}, config)
        end
      end

      describe ".read_key" do
        let :config do
          {key: stored_key, iv: stored_iv}
        end

        let :config_key do
          SymmetricEncryption::Keystore.read_key(**config)
        end

        let :dek_file_name do
          "#{the_test_path}/dek_tester_dek.encrypted_key"
        end

        describe "key" do
          it "key" do
            assert_equal stored_key, config_key.key
          end

          it "iv" do
            assert_equal stored_iv, config_key.iv
          end

          it "cipher_name" do
            assert_equal "aes-256-cbc", config_key.cipher_name
          end
        end

        describe "encrypted_key" do
          let :config do
            {encrypted_key: key2.encrypt(stored_key), iv: stored_iv, key_encrypting_key: {key: stored_key2, iv: stored_iv2}}
          end

          it "key" do
            assert_equal stored_key, config_key.key
          end

          it "iv" do
            assert_equal stored_iv, config_key.iv
          end

          it "cipher_name" do
            assert_equal "aes-256-cbc", config_key.cipher_name
          end
        end

        describe "key_filename" do
          let :config do
            File.open(dek_file_name, "wb", 0o600) { |f| f.write(key2.encrypt(stored_key)) }
            {key_filename: dek_file_name, iv: stored_iv, key_encrypting_key: {key: stored_key2, iv: stored_iv2}}
          end

          it "key" do
            assert_equal stored_key, config_key.key
          end

          it "iv" do
            assert_equal stored_iv, config_key.iv
          end

          it "cipher_name" do
            assert_equal "aes-256-cbc", config_key.cipher_name
          end
        end

        describe "key_env_var" do
          let :env_var do
            "TEST_KEY"
          end

          let :config do
            ENV[env_var] = ::Base64.strict_encode64(key2.encrypt(stored_key))
            {key_env_var: env_var, iv: stored_iv, key_encrypting_key: {key: stored_key2, iv: stored_iv2}}
          end

          it "key" do
            assert_equal stored_key, config_key.key
          end

          it "iv" do
            assert_equal stored_iv, config_key.iv
          end

          it "cipher_name" do
            assert_equal "aes-256-cbc", config_key.cipher_name
          end
        end

        describe "file store with kekek" do
          let :kekek_file_name do
            "#{the_test_path}/tester_kekek.key"
          end

          let :config do
            File.open(dek_file_name, "wb", 0o600) { |f| f.write(key2.encrypt(stored_key)) }
            encrypted_key = key3.encrypt(stored_key2)
            File.open(kekek_file_name, "wb", 0o600) { |f| f.write(stored_key3) }
            {
              key_filename:       dek_file_name,
              iv:                 stored_iv,
              key_encrypting_key: {
                encrypted_key:      encrypted_key,
                iv:                 stored_iv2,
                key_encrypting_key: {
                  key_filename: kekek_file_name,
                  iv:           stored_iv3
                }
              }
            }
          end

          it "key" do
            assert_equal stored_key, config_key.key
          end

          it "iv" do
            assert_equal stored_iv, config_key.iv
          end

          it "cipher_name" do
            assert_equal "aes-256-cbc", config_key.cipher_name
          end
        end
      end
    end
  end
end
