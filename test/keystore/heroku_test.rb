require_relative '../test_helper'
require 'stringio'

module SymmetricEncryption
  class HerokuTest < Minitest::Test
    describe SymmetricEncryption::Keystore::Heroku do
      describe '.generate_data_key' do
        let :version do
          10
        end

        let :keystore_config do
          SymmetricEncryption::Keystore::Heroku.generate_data_key(
            cipher_name: 'aes-256-cbc',
            app_name:    'tester',
            environment: 'test',
            version:     version
          )
        end

        it 'increments the version' do
          assert_equal 11, keystore_config[:version]
        end

        describe 'with 255 version' do
          let :version do
            255
          end

          it 'handles version wrap' do
            assert_equal 1, keystore_config[:version]
          end
        end

        describe 'with 0 version' do
          let :version do
            0
          end

          it 'increments version' do
            assert_equal 1, keystore_config[:version]
          end
        end

        it 'retains the env var name' do
          assert_equal 'TESTER_TEST_V11', keystore_config[:key_env_var]
        end

        it 'retains cipher_name' do
          assert_equal 'aes-256-cbc', keystore_config[:cipher_name]
        end
      end

      describe '#read' do
        let :key do
          SymmetricEncryption::Key.new
        end

        let :keystore do
          SymmetricEncryption::Keystore::Heroku.new(key_env_var: 'TESTER_ENV_VAR', key_encrypting_key: key)
        end

        it 'reads the key' do
          ENV['TESTER_ENV_VAR'] = Base64.strict_encode64(key.encrypt('TEST'))
          assert_equal 'TEST', keystore.read
        end
      end
    end
  end
end
