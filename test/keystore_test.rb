require_relative 'test_helper'

module SymmetricEncryption
  class KeystoreTest < Minitest::Test
    describe SymmetricEncryption::Keystore do
      let :keystore do
        SymmetricEncryption::Keystore::File.new(file_name: 'tmp/tester.key', key_encrypting_key: SymmetricEncryption::Key.new)
      end

      let :the_test_path do
        path = 'tmp/keystore_test'
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
        '1234567890ABCDEF1234567890ABCDEF'
      end

      let :stored_iv do
        'ABCDEF1234567890'
      end

      let :key do
        SymmetricEncryption::Key.new(key: stored_key, iv: stored_iv)
      end

      let :stored_key2 do
        'ABCDEF1234567890ABCDEF1234567890'
      end

      let :stored_iv2 do
        '1234567890ABCDEF'
      end

      let :key2 do
        SymmetricEncryption::Key.new(key: stored_key2, iv: stored_iv2)
      end

      let :stored_key3 do
        'ABCDEF0123456789ABCDEF0123456789'
      end

      let :stored_iv3 do
        '0123456789ABCDEF'
      end

      let :key3 do
        SymmetricEncryption::Key.new(key: stored_key3, iv: stored_iv3)
      end

      describe '.generate_data_keys' do
        let :environments do
          %i[development test acceptance preprod production]
        end

        let :config do
          SymmetricEncryption::Keystore.generate_data_keys(
            keystore:     :file,
            key_path:     the_test_path,
            app_name:     'tester',
            environments: environments,
            cipher_name:  'aes-128-cbc'
          )
        end

        it 'creates keys for each environment' do
          assert_equal environments, config.keys, config
        end

        it 'use test config for development and test' do
          assert_equal SymmetricEncryption::Keystore.dev_config, config[:test]
          assert_equal SymmetricEncryption::Keystore.dev_config, config[:development]
        end
      end

      describe '.rotate_keys' do
        let :environments do
          %i[development test acceptance preprod production]
        end

        let :config do
          SymmetricEncryption::Keystore.generate_data_keys(
            keystore:     :file,
            key_path:     the_test_path,
            app_name:     'tester',
            environments: environments,
            cipher_name:  'aes-128-cbc'
          )
        end

        let :rolling_deploy do
          false
        end

        let :key_rotation do
          SymmetricEncryption::Keystore.rotate_keys!(
            config,
            environments:   environments,
            app_name:       'tester',
            rolling_deploy: rolling_deploy
          )
        end

        it 'creates an encrypted key file for all non-test environments' do
          (environments - %i[development test]).each do |env|
            assert key_rotation
            assert key_rotation[env.to_sym], key_rotation
            assert key_rotation[env.to_sym][:ciphers]
            assert ciphers = key_rotation[env.to_sym][:ciphers], "Environment #{env} is missing ciphers: #{key_rotation[env.to_sym].inspect}"
            assert_equal 2, ciphers.size, "Environment #{env}: #{ciphers.inspect}"
            assert new_config = ciphers.first
            assert file_name  = new_config[:key_filename], "Environment #{env} is missing key_filename: #{ciphers.inspect}"
            assert File.exist?(file_name)
            assert_equal 2, new_config[:version]
          end
        end
      end

      describe '.read_key' do
        let :config do
          {key: stored_key, iv: stored_iv}
        end

        let :config_key do
          SymmetricEncryption::Keystore.read_key(config)
        end

        let :dek_file_name do
          "#{the_test_path}/dek_tester_dek.encrypted_key"
        end

        describe 'key' do
          it 'key' do
            assert_equal stored_key, config_key.key
          end

          it 'iv' do
            assert_equal stored_iv, config_key.iv
          end

          it 'cipher_name' do
            assert_equal 'aes-256-cbc', config_key.cipher_name
          end
        end

        describe 'encrypted_key' do
          let :config do
            {encrypted_key: key2.encrypt(stored_key), iv: stored_iv, key_encrypting_key: {key: stored_key2, iv: stored_iv2}}
          end

          it 'key' do
            assert_equal stored_key, config_key.key
          end

          it 'iv' do
            assert_equal stored_iv, config_key.iv
          end

          it 'cipher_name' do
            assert_equal 'aes-256-cbc', config_key.cipher_name
          end
        end

        describe 'key_filename' do
          let :config do
            File.open(dek_file_name, 'wb') { |f| f.write(key2.encrypt(stored_key)) }
            {key_filename: dek_file_name, iv: stored_iv, key_encrypting_key: {key: stored_key2, iv: stored_iv2}}
          end

          it 'key' do
            assert_equal stored_key, config_key.key
          end

          it 'iv' do
            assert_equal stored_iv, config_key.iv
          end

          it 'cipher_name' do
            assert_equal 'aes-256-cbc', config_key.cipher_name
          end
        end

        describe 'key_env_var' do
          let :env_var do
            'TEST_KEY'
          end

          let :config do
            ENV[env_var] = ::Base64.strict_encode64(key2.encrypt(stored_key))
            {key_env_var: env_var, iv: stored_iv, key_encrypting_key: {key: stored_key2, iv: stored_iv2}}
          end

          it 'key' do
            assert_equal stored_key, config_key.key
          end

          it 'iv' do
            assert_equal stored_iv, config_key.iv
          end

          it 'cipher_name' do
            assert_equal 'aes-256-cbc', config_key.cipher_name
          end
        end

        describe 'file store with kekek' do
          let :kekek_file_name do
            "#{the_test_path}/tester_kekek.key"
          end

          let :config do
            File.open(dek_file_name, 'wb') { |f| f.write(key2.encrypt(stored_key)) }
            encrypted_key = key3.encrypt(stored_key2)
            File.open(kekek_file_name, 'wb') { |f| f.write(stored_key3) }
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

          it 'key' do
            assert_equal stored_key, config_key.key
          end

          it 'iv' do
            assert_equal stored_iv, config_key.iv
          end

          it 'cipher_name' do
            assert_equal 'aes-256-cbc', config_key.cipher_name
          end
        end
      end
    end
  end
end
