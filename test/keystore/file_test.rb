require_relative '../test_helper'
require 'stringio'

module SymmetricEncryption
  class FileTest < Minitest::Test
    describe SymmetricEncryption::Keystore::File do
      after do
        # Cleanup generated encryption key files.
        `rm tmp/tester* 2> /dev/null`
      end

      describe '.new_key_config' do
        let :version do
          10
        end

        let :key_config do
          SymmetricEncryption::Keystore::File.new_key_config(
            key_path:           'tmp',
            cipher_name:        'aes-256-cbc',
            app_name:           'tester',
            environment:        'test',
            version:            version
          )
        end

        it 'increments the version' do
          assert_equal 11, key_config[:version]
        end

        describe 'with 255 version' do
          let :version do
            255
          end

          it 'handles version wrap' do
            assert_equal 1, key_config[:version]
          end
        end

        describe 'with 0 version' do
          let :version do
            0
          end

          it 'increments version' do
            assert_equal 1, key_config[:version]
          end
        end

        it 'creates the encrypted key file' do
          file_name = 'tmp/tester_test_v11.encrypted_key'
          assert_equal file_name, key_config[:key_filename]
          assert File.exist?(file_name)
        end

        it 'retains cipher_name' do
          assert_equal 'aes-256-cbc', key_config[:cipher_name]
        end

        it 'is readable by Key.from_config' do
          key_config.delete(:version)
          assert key = SymmetricEncryption::Key.from_config(key_config)
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
          assert_equal SymmetricEncryption::Keystore.dev_config, config[:test]
          assert_equal SymmetricEncryption::Keystore.dev_config, config[:development]
        end

        it 'each non test environment has a key encryption key' do
          (environments - %i(development test)).each do |env|
            assert config[env][:ciphers].first[:key_encrypting_key], "Environment #{env} is missing the key encryption key"
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
        let :keystore do
          SymmetricEncryption::Keystore::File.new(file_name: 'tmp/tester.key', key_encrypting_key: SymmetricEncryption::Key.new)
        end

        it 'stores the key' do
          keystore.write('TEST')
          assert_equal 'TEST', keystore.read
        end
      end

    end
  end
end
