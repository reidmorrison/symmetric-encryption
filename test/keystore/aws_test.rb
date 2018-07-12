require_relative '../test_helper'
require 'stringio'

module SymmetricEncryption
  module Keystore
    class FileTest < Minitest::Test
      describe SymmetricEncryption::Keystore::File do
        before do
          unless (ENV['AWS_ACCESS_KEY_ID'] && ENV['AWS_SECRET_ACCESS_KEY']) || ENV['AWS_CONFIG_FILE']
            # For example: export AWS_CONFIG_FILE=~/.aws/credentials
            skip 'Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or AWS_CONFIG_FILE to run AWS KMS tests'
          end
        end

        after do
          # Cleanup generated encryption key files.
          `rm -r tmp/test_path 2> /dev/null`
        end

        let :regions do
          %w[us-east-1 us-east-2]
        end

        let :version do
          10
        end

        let :key_config do
          SymmetricEncryption::Keystore::Aws.generate_data_key(
            regions:     regions,
            key_path:    'tmp/test_path',
            cipher_name: 'aes-256-cbc',
            app_name:    'tester',
            environment: 'test',
            version:     version
          )
        end

        let :master_key_alias do
          'alias/symmetric-encryption/test'
        end

        describe '.generate_data_key' do
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

          it 'creates encrypted key file for every region' do
            assert key_files = key_config[:key_files]
            common_data_key          = nil
            first_encrypted_data_key = nil
            key_files.each do |key_file|
              assert region = key_file[:region]
              assert file_name = key_file[:file_name]
              expected_file_name = "tmp/test_path/tester_test_#{region}_v11.encrypted_key"

              assert_equal expected_file_name, file_name
              assert ::File.exist?(file_name)

              assert encrypted_data_key = ::File.read(file_name)
              ap "ENCRYPTED"
              ap encrypted_data_key

              # keystore = SymmetricEncryption::Keystore::Aws.new(region: region, )
              # assert data_key = keystore.aws.decrypt(encrypted_data_key)
              #
              # ap "DATA KEY"
              # ap data_key
              #
              # # Verify that the dek is the same in every region, but encrypted with the CMK for that region.
              # if common_data_key
              #   refute_equal encrypted_data_key, first_encrypted_data_key, 'Must be encrypted with region specific CMK'
              #   assert_equal common_data_key, data_key, 'All regions must have the same data key'
              # else
              #   common_data_key          = data_key
              #   first_encrypted_data_key = encrypted_data_key
              # end
            end
          end

          it 'retains cipher_name' do
            assert_equal 'aes-256-cbc', key_config[:cipher_name]
          end

          it 'is readable by Keystore.from_config' do
            ENV['AWS_REGION'] = 'us-east-1'
            assert SymmetricEncryption::Keystore.read_key(key_config)
          end
        end

        describe '#write, #read' do
          let :keystore do
            SymmetricEncryption::Keystore::Aws.new(
              region:           'us-east-1',
              master_key_alias: master_key_alias,
              key_files:        [{region: 'us-east-1', file_name: 'tmp/test_path/file_1'}]
            )
          end

          it 'stores the key' do
            keystore.write('TEST')
            assert_equal 'TEST', keystore.read
          end
        end
      end
    end
  end
end
