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
              assert_path_exists key_file[:file_name], "Missing key file for #{key_file[:region]}"
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

          it "creates every key file readable by its owner alone" do
            key_config[:key_files].each do |key_file|
              assert_equal "100600", ::File.stat(key_file[:file_name]).mode.to_s(8)
            end
          end

          describe "with supplied key file expectations" do
            let :key_config do
              SymmetricEncryption::Keystore::Aws.generate_data_key(
                regions:     regions,
                key_path:    the_test_path,
                cipher_name: "aes-256-cbc",
                app_name:    "tester",
                environment: "test",
                version:     10,
                permissions: "0644",
                owner:       Process.uid,
                group:       "root"
              )
            end

            it "creates every key file with those permissions" do
              key_config[:key_files].each do |key_file|
                assert_equal "100644", ::File.stat(key_file[:file_name]).mode.to_s(8)
              end
            end

            it "records them once, covering every region" do
              assert_equal "0644", key_config[:permissions]
              assert_equal Process.uid, key_config[:owner]
              assert_equal "root", key_config[:group]
            end

            it "is readable by Keystore.read_key" do
              key_config.delete(:group)

              assert_equal data_key, SymmetricEncryption::Keystore.read_key(**key_config, region: regions.first).key
            end
          end
        end

        describe ".master_key_alias" do
          it "names the master key after every environment, not just the first" do
            assert_equal "alias/symmetric-encryption/tester/release",
                         SymmetricEncryption::Keystore::Aws.master_key_alias("tester", "release")
            assert_equal "alias/symmetric-encryption/tester/production",
                         SymmetricEncryption::Keystore::Aws.master_key_alias("tester", "production")
          end
        end

        describe "key rotation" do
          let :config do
            SymmetricEncryption::Keystore.generate_data_keys(
              keystore:     :aws,
              key_path:     the_test_path,
              app_name:     "tester",
              environments: %i[development test production],
              regions:      regions,
              cipher_name:  "aes-256-cbc"
            )
          end

          let :key_rotation do
            SymmetricEncryption::Keystore.rotate_keys!(config, app_name: "tester")
          end

          it "adds a new key version" do
            ciphers = key_rotation[:production][:ciphers]

            assert_equal 2, ciphers.size
            assert_equal 2, ciphers.first[:version]
            assert_equal :aws, ciphers.first[:keystore]
          end

          it "writes the new key files alongside the current ones" do
            key_rotation[:production][:ciphers].first[:key_files].each do |key_file|
              assert_path_exists key_file[:file_name]
              assert_equal the_test_path, ::File.dirname(key_file[:file_name])
            end
          end

          it "keeps the regions the current key files cover" do
            key_files = key_rotation[:production][:ciphers].first[:key_files]

            assert_equal(regions, key_files.collect { |key_file| key_file[:region] })
          end

          it "names the master key after the environment being rotated" do
            new_config = key_rotation[:production][:ciphers].first

            assert_equal "alias/symmetric-encryption/tester/production", new_config[:master_key_alias]
          end

          it "leaves development and test alone, since they hold their key in the config file" do
            assert_equal SymmetricEncryption::Keystore.dev_config, key_rotation[:development]
            assert_equal SymmetricEncryption::Keystore.dev_config, key_rotation[:test]
          end

          it "writes to the supplied key path and regions instead" do
            other_path = "#{the_test_path}/rotated"
            FileUtils.makedirs(other_path)

            rotated = SymmetricEncryption::Keystore.rotate_keys!(
              config,
              app_name: "tester",
              key_path: other_path,
              regions:  %w[eu-west-1]
            )
            key_files = rotated[:production][:ciphers].first[:key_files]

            assert_equal(%w[eu-west-1], key_files.collect { |key_file| key_file[:region] })
            assert_equal other_path, ::File.dirname(key_files.first[:file_name])
            assert_path_exists key_files.first[:file_name]
          end

          it "migrates to another keystore, keeping the current key path" do
            rotated    = SymmetricEncryption::Keystore.rotate_keys!(config, app_name: "tester", keystore: :file)
            new_config = rotated[:production][:ciphers].first

            assert_equal :file, new_config[:keystore]
            assert_equal the_test_path, ::File.dirname(new_config[:key_filename])
            assert_path_exists new_config[:key_filename]
          end

          it "leaves the key encrypting key to AWS KMS" do
            before  = Marshal.load(Marshal.dump(config[:production][:ciphers]))
            rotated = SymmetricEncryption::Keystore.rotate_key_encrypting_keys!(config, app_name: "tester")

            assert_equal before, rotated[:production][:ciphers]
          end
        end

        describe "#read" do
          it "refuses a key file that can be read by others" do
            file_name = key_config[:key_files].first[:file_name]
            FileUtils.chmod(0o666, file_name)

            error = assert_raises(SymmetricEncryption::ConfigError) do
              SymmetricEncryption::Keystore.read_key(**key_config, region: regions.first)
            end

            assert_includes error.message, "has the wrong permissions: 0666. Expected 0600 or 0400."
          end

          it "reads a key file that has the permissions the config supplies" do
            file_name = key_config[:key_files].first[:file_name]
            FileUtils.chmod(0o644, file_name)
            key = SymmetricEncryption::Keystore.read_key(**key_config, region: regions.first, permissions: "0644")

            assert_equal data_key, key.key
          end

          it "refuses a key file owned by another user" do
            error = assert_raises(SymmetricEncryption::ConfigError) do
              SymmetricEncryption::Keystore.read_key(**key_config, region: regions.first, owner: Process.uid + 1)
            end

            assert_includes error.message, "has the wrong owner:"
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
