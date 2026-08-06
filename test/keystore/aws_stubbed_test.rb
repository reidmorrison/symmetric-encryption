require_relative "../test_helper"
require "aws-sdk-kms"

module SymmetricEncryption
  module Keystore
    # Runs against the AWS SDK's built-in response stubbing, so it needs no credentials
    # and makes no network calls.
    #
    # See test/keystore/aws_test.rb for the tests that talk to KMS itself.
    class AwsStubbedTest < Minitest::Test
      describe SymmetricEncryption::Keystore::Aws do
        let :the_test_path do
          "tmp/keystore/aws_stubbed_test"
        end

        let :regions do
          %w[us-east-1 us-east-2]
        end

        let :data_key do
          SymmetricEncryption::Key.new(cipher_name: "aes-256-cbc").key
        end

        let :key_config do
          SymmetricEncryption::Keystore::Aws.generate_data_key(
            regions:     regions,
            key_path:    the_test_path,
            cipher_name: "aes-256-cbc",
            app_name:    "tester",
            environment: "test",
            version:     10
          )
        end

        before do
          FileUtils.rm_rf(the_test_path)
          FileUtils.makedirs(the_test_path)

          @previous_stub_responses      = ::Aws.config[:stub_responses]
          # Applied to every client created from here on, including those built internally.
          ::Aws.config[:stub_responses] = {
            generate_data_key: {plaintext: data_key, ciphertext_blob: "encrypted-data-key"},
            encrypt:           {ciphertext_blob: "encrypted-data-key"},
            decrypt:           {plaintext: data_key}
          }
        end

        after do
          if @previous_stub_responses.nil?
            ::Aws.config.delete(:stub_responses)
          else
            ::Aws.config[:stub_responses] = @previous_stub_responses
          end
          FileUtils.rm_rf(the_test_path)
        end

        describe ".generate_data_key" do
          it "increments the version" do
            assert_equal 11, key_config[:version]
          end

          it "handles version wrap" do
            config = SymmetricEncryption::Keystore::Aws.generate_data_key(
              regions:     regions,
              key_path:    the_test_path,
              cipher_name: "aes-256-cbc",
              app_name:    "tester",
              environment: "test",
              version:     255
            )

            assert_equal 1, config[:version]
          end

          it "retains cipher_name" do
            assert_equal "aes-256-cbc", key_config[:cipher_name]
          end

          it "names the master key after the app and environment" do
            assert_equal "alias/symmetric-encryption/tester/test", key_config[:master_key_alias]
          end

          it "creates an encrypted key file for every region" do
            assert_equal(regions, key_config[:key_files].collect { |i| i[:region] })

            key_config[:key_files].each do |key_file|
              assert ::File.exist?(key_file[:file_name]), "Missing key file for #{key_file[:region]}"
              assert_includes key_file[:file_name], "tester_test_#{key_file[:region]}_v11.encrypted_key"
            end
          end

          it "writes the encrypted key, never the key itself" do
            file_name = key_config[:key_files].first[:file_name]

            assert_equal "encrypted-data-key", ::Base64.strict_decode64(::File.read(file_name))
          end

          it "is readable by Keystore.read_key" do
            key = SymmetricEncryption::Keystore.read_key(**key_config, region: regions.first)

            assert_equal data_key, key.key
            assert_equal key_config[:iv], key.iv
          end

          it "accepts a supplied data encrypting key" do
            dek = SymmetricEncryption::Key.new(cipher_name: "aes-256-cbc")

            config = SymmetricEncryption::Keystore::Aws.generate_data_key(
              regions:     regions,
              key_path:    the_test_path,
              cipher_name: "aes-256-cbc",
              app_name:    "tester",
              environment: "test",
              version:     1,
              dek:         dek
            )

            assert_equal dek.iv, config[:iv]
          end
        end

        describe "#initialize" do
          it "refuses a key encrypting key" do
            error = assert_raises(SymmetricEncryption::ConfigError) do
              SymmetricEncryption::Keystore::Aws.new(
                key_files:          [{region: "us-east-1", file_name: "tester.key"}],
                master_key_alias:   "alias/tester",
                key_encrypting_key: SymmetricEncryption::Key.new
              )
            end

            assert_includes error.message, "does not support supplying a key_encrypting_key"
          end

          it "defaults the region from the environment" do
            previous          = ENV.fetch("AWS_REGION", nil)
            ENV["AWS_REGION"] = "us-west-1"

            keystore = SymmetricEncryption::Keystore::Aws.new(
              key_files:        [{region: "us-west-1", file_name: "tester.key"}],
              master_key_alias: "alias/tester"
            )

            assert_equal "us-west-1", keystore.region
          ensure
            previous ? ENV["AWS_REGION"] = previous : ENV.delete("AWS_REGION")
          end
        end

        describe "#read" do
          it "raises when there is no key file for the region" do
            keystore = SymmetricEncryption::Keystore::Aws.new(
              key_files:        key_config[:key_files],
              master_key_alias: key_config[:master_key_alias],
              region:           "eu-west-1"
            )

            error = assert_raises(SymmetricEncryption::ConfigError) { keystore.read }

            assert_includes error.message, "region: eu-west-1 not available in the supplied key_files"
          end
        end

        describe "#write" do
          it "raises when a key file entry is incomplete" do
            keystore = SymmetricEncryption::Keystore::Aws.new(
              key_files:        [{region: "us-east-1"}],
              master_key_alias: "alias/tester",
              region:           "us-east-1"
            )

            assert_raises(ArgumentError) { keystore.write(data_key) }
          end
        end
      end
    end
  end
end
