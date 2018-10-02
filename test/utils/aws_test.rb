require_relative '../test_helper'
require 'stringio'

module SymmetricEncryption
  module Utils
    class AwsTest < Minitest::Test
      describe SymmetricEncryption::Utils::Aws do
        before do
          unless (ENV['AWS_ACCESS_KEY_ID'] && ENV['AWS_SECRET_ACCESS_KEY']) || ENV['AWS_CONFIG_FILE']
            # For example: export AWS_CONFIG_FILE=~/.aws/credentials
            skip 'Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or AWS_CONFIG_FILE to run AWS KMS tests'
          end
        end

        let :region do
          'us-east-1'
        end

        let :master_key_alias do
          'alias/symmetric-encryption/test'
        end

        let :aws do
          SymmetricEncryption::Utils::Aws.new(region: region, master_key_alias: master_key_alias)
        end

        describe '#key_spec' do
          it 'converts aes-256-cbc' do
            assert_equal 'AES_256', aws.key_spec('aes-256-cbc')
          end

          it 'converts aes-128-cbc' do
            assert_equal 'AES_128', aws.key_spec('aes-128-cbc')
          end
        end

        describe '#create_master_key' do
          it 'creates a new master key' do
            skip 'Only run if really needed, gets tested once as part of the CMK auto-create'
            aws.delete_master_key(retention_days: 7)
            aws.create_master_key
          end
        end

        describe '#generate_data_key' do
          it 'creates a new data key' do
            assert aws.generate_data_key('aes-128-cbc')
          end
        end

        describe '#generate_encrypted_data_key' do
          it 'creates a new data key' do
            assert aws.generate_encrypted_data_key('aes-128-cbc')
          end
        end

        describe '#encrypt' do
          it 'encrypts a block of data' do
            assert aws.encrypt('hello')
          end
        end

        describe '#decrypt' do
          it 'decrypts a previously encrypted block of data' do
            message   = 'hello world this is a top secret message'
            encrypted = aws.encrypt(message)
            decrypted = aws.decrypt(encrypted)
            assert_equal message, decrypted
          end
        end
      end
    end
  end
end
