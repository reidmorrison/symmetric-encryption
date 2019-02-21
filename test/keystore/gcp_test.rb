require_relative '../test_helper'

module SymmetricEncryption
  module Keystore
    class GcpTest < Minitest::Test
      describe SymmetricEncryption::Keystore::Gcp do
        before do
          unless ENV['GOOGLE_CLOUD_KEYFILE']
            skip 'Set GOOGLE_CLOUD_KEYFILE to run Google Cloud Platform KMS tests'
          end
        end

        let(:the_test_path) do
          path = 'tmp/keystore/gcp_test'
          FileUtils.makedirs(path) unless ::File.exist?(path)
          path
        end

        describe ".generate_data_key" do
          after do
            # Cleanup generated encryption key files.
            `rm #{the_test_path}/* 2> /dev/null`
          end

          let :version do
            10
          end

          let :key_config do
            SymmetricEncryption::Keystore::Gcp.generate_data_key(
            key_path:    the_test_path,
            cipher_name: 'aes-256-cbc',
            app_name:    'tester',
            environment: 'test',
            version:     version
            )
          end

          # TODO: reuse versioning tests from aws_test.rb

          it 'creates encrypted key file' do
            assert key_path = key_config[:crypto_key]
            assert file_name   = key_config[:key_file]
            expected_file_name = "#{the_test_path}/tester_test_v11.encrypted_key"

            assert_equal expected_file_name, file_name
            assert ::File.exist?(file_name)

            assert encoded_data_key = ::File.read(file_name)
            encrypted_data_key      = Base64.strict_decode64(encoded_data_key)
            assert SymmetricEncryption::Keystore::Gcp::KMS::KeyManagementServiceClient.new.decrypt(key_path, encrypted_data_key)
          end

          it 'is readable by Keystore.read_key' do
            assert SymmetricEncryption::Keystore.read_key(key_config)
          end
        end

        describe '#write, #read' do
          let(:keystore) do
            SymmetricEncryption::Keystore::Gcp.new(
            key_file:    "#{the_test_path}/file_1",
            app_name:    'tester',
            environment: 'test'
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
