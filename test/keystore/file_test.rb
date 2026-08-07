require_relative "../test_helper"
require "stringio"
require "fileutils"

module SymmetricEncryption
  class FileTest < Minitest::Test
    describe SymmetricEncryption::Keystore::File do
      let :the_test_path do
        path = "tmp/keystore/file_test"
        FileUtils.makedirs(path)
        path
      end

      after do
        # Cleanup generated encryption key files.
        `rm #{the_test_path}/* 2> /dev/null`
      end

      describe ".generate_data_key" do
        let :version do
          10
        end

        let :key_config do
          SymmetricEncryption::Keystore::File.generate_data_key(
            key_path:    the_test_path,
            cipher_name: "aes-256-cbc",
            app_name:    "tester",
            environment: "test",
            version:     version
          )
        end

        it "increments the version" do
          assert_equal 11, key_config[:version]
        end

        describe "with 255 version" do
          let :version do
            255
          end

          it "handles version wrap" do
            assert_equal 1, key_config[:version]
          end
        end

        describe "with 0 version" do
          let :version do
            0
          end

          it "increments version" do
            assert_equal 1, key_config[:version]
          end
        end

        it "creates the encrypted key file with the correct permissions" do
          file_name = "#{the_test_path}/tester_test_v11.encrypted_key"

          assert_equal file_name, key_config[:key_filename]
          assert_path_exists file_name
          assert_equal "100600", File.stat(file_name).mode.to_s(8)
        end

        it "retains cipher_name" do
          assert_equal "aes-256-cbc", key_config[:cipher_name]
        end

        it "is readable by Key.from_config" do
          key_config.delete(:version)

          assert SymmetricEncryption::Keystore.read_key(**key_config)
        end

        describe "with supplied permissions" do
          let :key_config do
            SymmetricEncryption::Keystore::File.generate_data_key(
              key_path:    the_test_path,
              cipher_name: "aes-256-cbc",
              app_name:    "tester",
              environment: "test",
              version:     version,
              permissions: "0640"
            )
          end

          it "creates both key files with those permissions" do
            kekek_file_name = key_config[:key_encrypting_key][:key_encrypting_key][:key_filename]

            assert_equal "100640", File.stat(key_config[:key_filename]).mode.to_s(8)
            assert_equal "100640", File.stat(kekek_file_name).mode.to_s(8)
          end

          it "records them against every key file in the config" do
            assert_equal "0640", key_config[:permissions]
            assert_equal "0640", key_config[:key_encrypting_key][:key_encrypting_key][:permissions]
          end

          it "is readable by Key.from_config" do
            key_config.delete(:version)

            assert SymmetricEncryption::Keystore.read_key(**key_config)
          end
        end
      end

      describe "#write, #read" do
        let :keystore do
          SymmetricEncryption::Keystore::File.new(key_filename: "#{the_test_path}/tester.key", key_encrypting_key: SymmetricEncryption::Key.new)
        end

        after do
          FileUtils.chmod 0o600, Dir.glob("#{the_test_path}/*")
        end

        it "stores the key" do
          keystore.write("TEST")

          assert_equal "TEST", keystore.read
        end

        it "raises an exception when the file can be read/written by others" do
          keystore.write("TEST")
          FileUtils.chmod 0o666, Dir.glob("#{the_test_path}/*")
          assert_raises(SymmetricEncryption::ConfigError) { keystore.read }
        end

        it "names the permissions it found and the ones it expected" do
          keystore.write("TEST")
          FileUtils.chmod 0o666, Dir.glob("#{the_test_path}/*")
          error = assert_raises(SymmetricEncryption::ConfigError) { keystore.read }

          assert_includes error.message, "has the wrong permissions: 0666. Expected 0600 or 0400."
        end

        it "reads a file that is only readable by its owner" do
          keystore.write("TEST")
          FileUtils.chmod 0o400, Dir.glob("#{the_test_path}/*")

          assert_equal "TEST", keystore.read
        end
      end

      describe "#read with supplied permissions" do
        let :the_permissions do
          "0644"
        end

        let :keystore do
          SymmetricEncryption::Keystore::File.new(
            key_filename:       "#{the_test_path}/tester.key",
            key_encrypting_key: SymmetricEncryption::Key.new,
            permissions:        the_permissions
          )
        end

        after do
          FileUtils.chmod 0o600, Dir.glob("#{the_test_path}/*")
        end

        it "creates the key file with the supplied permissions" do
          keystore.write("TEST")

          assert_equal "100644", File.stat("#{the_test_path}/tester.key").mode.to_s(8)
        end

        it "reads a key file with the supplied permissions" do
          keystore.write("TEST")

          assert_equal "TEST", keystore.read
        end

        it "raises an exception when the file does not have the supplied permissions" do
          keystore.write("TEST")
          FileUtils.chmod 0o600, Dir.glob("#{the_test_path}/*")
          error = assert_raises(SymmetricEncryption::ConfigError) { keystore.read }

          assert_includes error.message, "has the wrong permissions: 0600. Expected 0644."
        end

        describe "supplied as an Integer" do
          let :the_permissions do
            0o644
          end

          it "reads a key file with the supplied permissions" do
            keystore.write("TEST")

            assert_equal "TEST", keystore.read
          end
        end

        describe "supplied as a list" do
          let :the_permissions do
            ["0644", 0o600]
          end

          it "creates the key file with the first permission" do
            keystore.write("TEST")

            assert_equal "100644", File.stat("#{the_test_path}/tester.key").mode.to_s(8)
          end

          it "accepts any permission in the list" do
            keystore.write("TEST")
            FileUtils.chmod 0o600, Dir.glob("#{the_test_path}/*")

            assert_equal "TEST", keystore.read
          end

          it "rejects a permission that is not in the list" do
            keystore.write("TEST")
            FileUtils.chmod 0o400, Dir.glob("#{the_test_path}/*")
            error = assert_raises(SymmetricEncryption::ConfigError) { keystore.read }

            assert_includes error.message, "Expected 0644 or 0600."
          end
        end

        describe "supplied an invalid value" do
          it "rejects a string that is not an octal file mode" do
            assert_raises(SymmetricEncryption::ConfigError) do
              SymmetricEncryption::Keystore::File.new(key_filename: "tester.key", permissions: "rw-r--r--")
            end
          end

          it "rejects a mode that includes the file type bits" do
            assert_raises(SymmetricEncryption::ConfigError) do
              SymmetricEncryption::Keystore::File.new(key_filename: "tester.key", permissions: "100644")
            end
          end

          it "rejects a value that is not a file mode at all" do
            assert_raises(SymmetricEncryption::ConfigError) do
              SymmetricEncryption::Keystore::File.new(key_filename: "tester.key", permissions: :world_readable)
            end
          end

          it "rejects an empty list" do
            assert_raises(SymmetricEncryption::ConfigError) do
              SymmetricEncryption::Keystore::File.new(key_filename: "tester.key", permissions: [])
            end
          end
        end
      end

      describe "read from a config" do
        let :key_config do
          SymmetricEncryption::Keystore::File.generate_data_key(
            key_path:    the_test_path,
            cipher_name: "aes-256-cbc",
            app_name:    "tester",
            environment: "test",
            version:     1,
            permissions: "0644"
          )
        end

        it "survives a round trip through the config file" do
          config_file_name = "#{the_test_path}/symmetric-encryption.yml"
          SymmetricEncryption::Config.write_file(config_file_name, {test: {ciphers: [key_config]}})
          config = SymmetricEncryption::Config.read_file(config_file_name)[:test][:ciphers].first

          assert_equal "0644", config[:permissions]
          assert_equal "0644", config[:key_encrypting_key][:key_encrypting_key][:permissions]

          config.delete(:version)

          assert SymmetricEncryption::Keystore.read_key(**config)
        end

        it "raises when a key file no longer has the permissions in the config file" do
          key_config.delete(:version)
          FileUtils.chmod 0o600, key_config[:key_filename]

          assert_raises(SymmetricEncryption::ConfigError) { SymmetricEncryption::Keystore.read_key(**key_config) }
        end
      end
    end
  end
end
