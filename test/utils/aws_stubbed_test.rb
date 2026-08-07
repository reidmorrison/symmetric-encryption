require_relative "../test_helper"
require "aws-sdk-kms"

module SymmetricEncryption
  module Utils
    # Runs against the AWS SDK's built-in response stubbing, so it needs no credentials
    # and makes no network calls. Request parameters are still validated against the real
    # KMS API model, so a misnamed or mistyped argument fails here.
    #
    # See test/utils/aws_test.rb for the tests that talk to KMS itself.
    class AwsStubbedTest < Minitest::Test
      describe SymmetricEncryption::Utils::Aws do
        let :master_key_alias do
          "alias/symmetric-encryption/tester/test"
        end

        let :data_key do
          SymmetricEncryption::Key.new(cipher_name: "aes-256-cbc").key
        end

        let :aws do
          SymmetricEncryption::Utils::Aws.new(region: "us-east-1", master_key_alias: master_key_alias)
        end

        before do
          @previous_stub_responses = ::Aws.config[:stub_responses]
          ::Aws.config[:stub_responses] = true
        end

        after do
          if @previous_stub_responses.nil?
            ::Aws.config.delete(:stub_responses)
          else
            ::Aws.config[:stub_responses] = @previous_stub_responses
          end
        end

        describe "#key_spec" do
          it "maps the supported OpenSSL ciphers" do
            assert_equal "AES_256", aws.key_spec("aes-256-cbc")
            assert_equal "AES_128", aws.key_spec("aes-128-cbc")
          end

          it "raises for an unmapped cipher" do
            error = assert_raises(RuntimeError) { aws.key_spec("aes-192-cbc") }

            assert_includes error.message, "has not yet been mapped to an AWS key spec"
          end
        end

        describe "#generate_data_key" do
          it "returns the key in the clear" do
            aws.client.stub_responses(:generate_data_key, plaintext: data_key, ciphertext_blob: "encrypted")

            assert_equal data_key, aws.generate_data_key("aes-256-cbc")
          end

          it "requests the key spec matching the cipher" do
            request = nil
            aws.client.stub_responses(:generate_data_key, lambda { |context|
              request = context.params
              {plaintext: data_key, ciphertext_blob: "encrypted"}
            })

            aws.generate_data_key("aes-128-cbc")

            assert_equal "AES_128", request[:key_spec]
            assert_equal master_key_alias, request[:key_id]
          end
        end

        describe "#generate_encrypted_data_key" do
          it "returns the encrypted key" do
            aws.client.stub_responses(:generate_data_key_without_plaintext, ciphertext_blob: "encrypted")

            assert_equal "encrypted", aws.generate_encrypted_data_key("aes-256-cbc")
          end
        end

        describe "#encrypt and #decrypt" do
          it "encrypts with the master key" do
            request = nil
            aws.client.stub_responses(:encrypt, lambda { |context|
              request = context.params
              {ciphertext_blob: "encrypted"}
            })

            assert_equal "encrypted", aws.encrypt(data_key)
            assert_equal master_key_alias, request[:key_id]
            assert_equal data_key, request[:plaintext]
          end

          it "decrypts without naming the master key" do
            request = nil
            aws.client.stub_responses(:decrypt, lambda { |context|
              request = context.params
              {plaintext: data_key}
            })

            assert_equal data_key, aws.decrypt("encrypted")
            assert_equal "encrypted", request[:ciphertext_blob]
          end
        end

        describe "#create_master_key" do
          it "creates the key and points the alias at it" do
            alias_request = nil
            aws.client.stub_responses(:create_key, key_metadata: {key_id: "new-key-id"})
            aws.client.stub_responses(:create_alias, lambda { |context|
              alias_request = context.params
              {}
            })

            assert_equal "new-key-id", aws.create_master_key
            assert_equal master_key_alias, alias_request[:alias_name]
            assert_equal "new-key-id", alias_request[:target_key_id]
          end
        end

        describe "auto creating the master key" do
          it "creates the master key and retries when it does not exist yet" do
            aws.client.stub_responses(:encrypt, ["NotFoundException", {ciphertext_blob: "encrypted"}])
            aws.client.stub_responses(:create_key, key_metadata: {key_id: "new-key-id"})
            aws.client.stub_responses(:create_alias, {})

            assert_equal "encrypted", aws.encrypt(data_key)
          end

          it "gives up after creating the master key once" do
            aws.client.stub_responses(:encrypt, "NotFoundException")
            aws.client.stub_responses(:create_key, key_metadata: {key_id: "new-key-id"})
            aws.client.stub_responses(:create_alias, {})

            assert_raises(::Aws::KMS::Errors::NotFoundException) { aws.encrypt(data_key) }
          end
        end

        describe "#delete_master_key" do
          it "returns nil when the master key does not exist" do
            aws.client.stub_responses(:describe_key, "NotFoundException")

            assert_nil aws.delete_master_key
          end

          it "schedules deletion and removes the alias" do
            deletion_request = nil
            alias_request    = nil
            deletion_date    = Time.now + (30 * 24 * 60 * 60)

            aws.client.stub_responses(:describe_key, key_metadata: {key_id: "the-key-id"})
            aws.client.stub_responses(:schedule_key_deletion, lambda { |context|
              deletion_request = context.params
              {key_id: "the-key-id", deletion_date: deletion_date}
            })
            aws.client.stub_responses(:delete_alias, lambda { |context|
              alias_request = context.params
              {}
            })

            assert_equal deletion_date.to_i, aws.delete_master_key(retention_days: 7).to_i
            assert_equal "the-key-id", deletion_request[:key_id]
            assert_equal 7, deletion_request[:pending_window_in_days]
            assert_equal master_key_alias, alias_request[:alias_name]
          end
        end
      end
    end
  end
end
