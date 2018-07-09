require_relative '../test_helper'
require 'stringio'

module SymmetricEncryption
  class FileTest < Minitest::Test
    describe SymmetricEncryption::Keystore::File do
      after do
        # Cleanup generated encryption key files.
        `rm tmp/tester* 2> /dev/null`
      end

      describe '.generate_data_key' do
        let :version do
          10
        end

        let :key_config do
          SymmetricEncryption::Keystore::File.generate_data_key(
            key_path:    'tmp',
            cipher_name: 'aes-256-cbc',
            app_name:    'tester',
            environment: 'test',
            version:     version
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
          assert SymmetricEncryption::Keystore.read_key(key_config)
        end
      end

      describe '#write, #read' do
        let :keystore do
          SymmetricEncryption::Keystore::File.new(key_filename: 'tmp/tester.key', key_encrypting_key: SymmetricEncryption::Key.new)
        end

        it 'stores the key' do
          keystore.write('TEST')
          assert_equal 'TEST', keystore.read
        end
      end
    end
  end
end
