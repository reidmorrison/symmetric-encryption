require_relative "../test_helper"
require "google/cloud/kms/v1"

module SymmetricEncryption
  module Keystore
    # Runs against a stubbed Cloud KMS client, so it needs no credentials and makes no
    # network calls.
    #
    # Unlike the AWS SDK, google-cloud-kms has no built-in response stubbing, so the client
    # itself is replaced. The stub returns the real response types and asserts on the real
    # request fields, so a change to the arguments this gem passes still fails here.
    #
    # See test/keystore/gcp_test.rb for the tests that talk to Cloud KMS itself.
    class GcpStubbedTest < Minitest::Test
      # Stands in for Google::Cloud::Kms::V1::KeyManagementService::Client.
      #
      # Encrypts by reversing, purely so that encrypt and decrypt are distinguishable, and
      # records every request so that the arguments this gem sends can be asserted on.
      class StubKmsClient
        attr_reader :encrypt_requests, :decrypt_requests

        def initialize
          @encrypt_requests = []
          @decrypt_requests = []
        end

        def encrypt(name:, plaintext:)
          @encrypt_requests << {name: name, plaintext: plaintext}
          Google::Cloud::Kms::V1::EncryptResponse.new(name: name, ciphertext: plaintext.reverse)
        end

        def decrypt(name:, ciphertext:)
          @decrypt_requests << {name: name, ciphertext: ciphertext}
          Google::Cloud::Kms::V1::DecryptResponse.new(plaintext: ciphertext.reverse)
        end
      end

      describe SymmetricEncryption::Keystore::Gcp do
        let :the_test_path do
          "tmp/keystore/gcp_stubbed_test"
        end

        let :stub_client do
          StubKmsClient.new
        end

        let :data_key do
          SymmetricEncryption::Key.new(cipher_name: "aes-256-cbc").key
        end

        before do
          FileUtils.rm_rf(the_test_path)
          FileUtils.makedirs(the_test_path)

          @previous_project             = ENV.fetch("GOOGLE_CLOUD_PROJECT", nil)
          ENV["GOOGLE_CLOUD_PROJECT"]   = "test-project"
        end

        after do
          @previous_project ? ENV["GOOGLE_CLOUD_PROJECT"] = @previous_project : ENV.delete("GOOGLE_CLOUD_PROJECT")
          FileUtils.rm_rf(the_test_path)
        end

        # Runs the block with every Gcp keystore talking to the stub client.
        def with_stubbed_client(&block)
          SymmetricEncryption::Keystore::Gcp.stub_any_instance(:client, stub_client, &block)
        end

        describe ".generate_data_key" do
          let :key_config do
            with_stubbed_client do
              SymmetricEncryption::Keystore::Gcp.generate_data_key(
                key_path:    the_test_path,
                cipher_name: "aes-256-cbc",
                app_name:    "tester",
                environment: "test",
                version:     10
              )
            end
          end

          it "increments the version" do
            assert_equal 11, key_config[:version]
          end

          it "handles version wrap" do
            config = with_stubbed_client do
              SymmetricEncryption::Keystore::Gcp.generate_data_key(
                key_path: the_test_path, cipher_name: "aes-256-cbc",
                app_name: "tester", environment: "test", version: 255
              )
            end

            assert_equal 1, config[:version]
          end

          it "retains cipher_name" do
            assert_equal "aes-256-cbc", key_config[:cipher_name]
          end

          it "writes the encrypted key file" do
            assert_path_exists key_config[:key_file]
            assert_includes key_config[:key_file], "tester_test_v11.encrypted_key"
          end

          it "writes the encrypted key, never the key itself" do
            contents = ::Base64.strict_decode64(::File.read(key_config[:key_file]))

            refute_equal contents, contents.reverse, "Key was written unencrypted"
          end

          it "records the fully qualified crypto key name" do
            assert_equal "projects/test-project/locations/global/keyRings/tester/cryptoKeys/test", key_config[:crypto_key]
          end

          it "accepts a supplied data encrypting key" do
            dek = SymmetricEncryption::Key.new(cipher_name: "aes-256-cbc")

            config = with_stubbed_client do
              SymmetricEncryption::Keystore::Gcp.generate_data_key(
                key_path: the_test_path, cipher_name: "aes-256-cbc",
                app_name: "tester", environment: "test", version: 1, dek: dek
              )
            end

            assert_equal dek.iv, config[:iv]
          end

          it "ignores the arguments meant for other keystores" do
            config = with_stubbed_client do
              SymmetricEncryption::Keystore::Gcp.generate_data_key(
                key_path: the_test_path, cipher_name: "aes-256-cbc", app_name: "tester",
                environment: "test", version: 1, regions: %w[us-east-1]
              )
            end

            assert_equal 2, config[:version]
          end
        end

        describe "#write and #read" do
          let :keystore do
            SymmetricEncryption::Keystore::Gcp.new(
              key_file:    "#{the_test_path}/tester.encrypted_key",
              app_name:    "tester",
              environment: "test"
            )
          end

          it "round trips the key through Cloud KMS" do
            with_stubbed_client do
              keystore.write(data_key)

              assert_equal data_key, keystore.read
            end
          end

          it "names the crypto key on every request" do
            with_stubbed_client do
              keystore.write(data_key)
              keystore.read
            end

            assert_equal([keystore.crypto_key], stub_client.encrypt_requests.collect { |r| r[:name] })
            assert_equal([keystore.crypto_key], stub_client.decrypt_requests.collect { |r| r[:name] })
          end

          it "sends the key as the plaintext to encrypt" do
            with_stubbed_client { keystore.write(data_key) }

            assert_equal data_key, stub_client.encrypt_requests.first[:plaintext]
          end
        end

        describe "#crypto_key" do
          it "uses the supplied crypto key when given" do
            keystore = SymmetricEncryption::Keystore::Gcp.new(
              key_file:   "#{the_test_path}/tester.encrypted_key",
              crypto_key: "projects/other/locations/global/keyRings/ring/cryptoKeys/key"
            )

            assert_equal "projects/other/locations/global/keyRings/ring/cryptoKeys/key", keystore.crypto_key
          end

          it "honors the location" do
            keystore = SymmetricEncryption::Keystore::Gcp.new(
              key_file:    "#{the_test_path}/tester.encrypted_key",
              app_name:    "tester",
              environment: "test",
              location_id: "us-east1"
            )

            assert_equal "projects/test-project/locations/us-east1/keyRings/tester/cryptoKeys/test", keystore.crypto_key
          end

          it "raises when the project is not set" do
            ENV.delete("GOOGLE_CLOUD_PROJECT")
            keystore = SymmetricEncryption::Keystore::Gcp.new(
              key_file: "#{the_test_path}/tester.encrypted_key", app_name: "tester", environment: "test"
            )

            error = assert_raises(RuntimeError) { keystore.crypto_key }

            assert_includes error.message, "GOOGLE_CLOUD_PROJECT must be set"
          end
        end

        describe "credentials" do
          let :keystore do
            SymmetricEncryption::Keystore::Gcp.new(
              key_file: "#{the_test_path}/tester.encrypted_key", app_name: "tester", environment: "test"
            )
          end

          it "reads the keyfile from the environment" do
            previous                    = ENV.fetch("GOOGLE_CLOUD_KEYFILE", nil)
            ENV["GOOGLE_CLOUD_KEYFILE"] = "/path/to/keyfile.json"

            assert_equal "/path/to/keyfile.json", keystore.send(:credentials)
          ensure
            previous ? ENV["GOOGLE_CLOUD_KEYFILE"] = previous : ENV.delete("GOOGLE_CLOUD_KEYFILE")
          end

          it "raises when the keyfile is not set" do
            previous = ENV.delete("GOOGLE_CLOUD_KEYFILE")

            error = assert_raises(RuntimeError) { keystore.send(:credentials) }

            assert_includes error.message, "GOOGLE_CLOUD_KEYFILE must be set"
          ensure
            ENV["GOOGLE_CLOUD_KEYFILE"] = previous if previous
          end

          it "uses the supplied credentials" do
            keystore = SymmetricEncryption::Keystore::Gcp.new(
              key_file: "#{the_test_path}/tester.encrypted_key", credentials: "supplied.json"
            )

            assert_equal "supplied.json", keystore.send(:credentials)
          end
        end
      end
    end
  end
end
