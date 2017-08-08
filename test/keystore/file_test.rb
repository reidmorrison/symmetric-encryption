require_relative '../test_helper'
require 'stringio'

module SymmetricEncryption
  class FileTest < Minitest::Test
    describe SymmetricEncryption::Keystore::File do
      let :key_encrypting_key do
        rsa_key = SymmetricEncryption::KeyEncryptingKey.generate_rsa_key
        SymmetricEncryption::KeyEncryptingKey.new(rsa_key)
      end

      let :keystore do
        SymmetricEncryption::Keystore::File.new(file_name: 'tmp/tester.key', key_encrypting_key: key_encrypting_key)
      end

      after do
        # Cleanup generated encryption key files.
        `rm tmp/tester*`
      end

      describe '.new_cipher' do
        let :version do
          10
        end

        let :keystore do
          SymmetricEncryption::Keystore::File.new_cipher(
            key_path:           'tmp',
            cipher_name:        'aes-256-cbc',
            key_encrypting_key: key_encrypting_key,
            app_name:           'tester',
            environment:        'test',
            version:            version
          )
        end

        it 'increments the version' do
          assert_equal 11, keystore[:version]
        end

        describe 'with 255 version' do
          let :version do
            255
          end

          it 'handles version wrap' do
            assert_equal 1, keystore[:version]
          end
        end

        describe 'with 0 version' do
          let :version do
            0
          end

          it 'increments version' do
            assert_equal 1, keystore[:version]
          end
        end

        it 'creates the encrypted key file' do
          file_name = 'tmp/tester_test_v11.key'
          assert_equal file_name, keystore[:key_filename]
          assert File.exist?(file_name)
        end

        it 'retains cipher_name' do
          assert_equal 'aes-256-cbc', keystore[:cipher_name]
        end
      end

      describe '.new_config' do
        let :environments do
          %i(development test acceptance preprod production)
        end

        let :config do
          SymmetricEncryption::Keystore::File.new_config(
            key_path:     'tmp',
            app_name:     'tester',
            environments: environments,
            cipher_name:  'aes-128-cbc'
          )
        end

        it 'creates keys for each environment' do
          assert_equal environments, config.keys, config
        end

        it 'use test config for development and test' do
          assert_equal SymmetricEncryption::Keystore::Memory.dev_config, config[:test]
          assert_equal SymmetricEncryption::Keystore::Memory.dev_config, config[:development]
        end

        it 'each non test environment has a key encryption key' do
          (environments - %i(development test)).each do |env|
            assert config[env][:ciphers].first[:key_encrypting_key].include?('BEGIN RSA PRIVATE KEY'), "Environment #{env} is missing the key encryption key"
          end
        end

        it 'every environment has ciphers' do
          environments.each do |env|
            assert ciphers = config[env][:ciphers], "Environment #{env} is missing ciphers: #{config[env].inspect}"
            assert_equal 1, ciphers.size
          end
        end

        it 'creates an encrypted key file for all non-test environments' do
          (environments - %i(development test)).each do |env|
            assert ciphers = config[env][:ciphers], "Environment #{env} is missing ciphers: #{config[env].inspect}"
            assert file_name = ciphers.first[:key_filename], "Environment #{env} is missing key_filename: #{ciphers.inspect}"
            assert File.exist?(file_name)
          end
        end
      end

      describe '#write, #read' do
        it 'stores the key' do
          keystore.write('TEST')
          assert_equal 'TEST', keystore.read
        end
      end

      describe '#write_encrypted' do
        it 'stores an encrypted key' do
          keystore.write_encrypted(key_encrypting_key.encrypt('TEST'))
          assert_equal 'TEST', keystore.read
        end
      end

    end
  end
end
