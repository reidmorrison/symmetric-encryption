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

        describe "with supplied key file expectations" do
          let :key_config do
            SymmetricEncryption::Keystore::File.generate_data_key(
              key_path:    the_test_path,
              cipher_name: "aes-256-cbc",
              app_name:    "tester",
              environment: "test",
              version:     version,
              permissions: "0640",
              owner:       Process.uid
            )
          end

          it "creates both key files with those permissions" do
            kekek_file_name = key_config[:key_encrypting_key][:key_encrypting_key][:key_filename]

            assert_equal "100640", File.stat(key_config[:key_filename]).mode.to_s(8)
            assert_equal "100640", File.stat(kekek_file_name).mode.to_s(8)
          end

          it "records them against every key file in the config" do
            kekek_config = key_config[:key_encrypting_key][:key_encrypting_key]

            assert_equal "0640", key_config[:permissions]
            assert_equal Process.uid, key_config[:owner]
            assert_equal "0640", kekek_config[:permissions]
            assert_equal Process.uid, kekek_config[:owner]
          end

          it "is readable by Key.from_config" do
            key_config.delete(:version)

            assert SymmetricEncryption::Keystore.read_key(**key_config)
          end

          it "records a group without changing the key files" do
            config = SymmetricEncryption::Keystore::File.generate_data_key(
              key_path:    the_test_path,
              cipher_name: "aes-256-cbc",
              app_name:    "tester",
              environment: "test",
              group:       "root"
            )

            assert_equal "root", config[:group]
            assert_equal "root", config[:key_encrypting_key][:key_encrypting_key][:group]
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

      describe "#read with a supplied owner" do
        let :the_owner do
          Process.uid
        end

        let :keystore do
          SymmetricEncryption::Keystore::File.new(
            key_filename:       "#{the_test_path}/tester.key",
            key_encrypting_key: SymmetricEncryption::Key.new,
            owner:              the_owner
          )
        end

        it "reads a key file owned by the supplied user id" do
          keystore.write("TEST")

          assert_equal "TEST", keystore.read
        end

        describe "supplied as a user name" do
          let :the_owner do
            Etc.getpwuid(Process.uid).name
          end

          it "reads a key file owned by the supplied user" do
            keystore.write("TEST")

            assert_equal "TEST", keystore.read
          end
        end

        describe "that does not own the key file" do
          let :the_owner do
            Process.uid + 1
          end

          it "raises an exception naming the owner it found" do
            keystore.write("TEST")
            error = assert_raises(SymmetricEncryption::ConfigError) { keystore.read }

            assert_includes error.message, "has the wrong owner:"
            assert_includes error.message, "(#{Process.uid})"
          end
        end

        describe "supplied as a list" do
          let :the_owner do
            [Process.uid + 1, Process.uid]
          end

          it "accepts any owner in the list" do
            keystore.write("TEST")

            assert_equal "TEST", keystore.read
          end
        end
      end

      describe "#read with a supplied group" do
        let :key_file_name do
          "#{the_test_path}/tester.key"
        end

        let :the_key_encrypting_key do
          SymmetricEncryption::Key.new
        end

        # The group a new file belongs to is decided by the platform, so read it back rather than
        # assuming it is the group of the process.
        let :the_group do
          File.stat(key_file_name).gid
        end

        def keystore_with(**args)
          SymmetricEncryption::Keystore::File.new(
            key_filename:       key_file_name,
            key_encrypting_key: the_key_encrypting_key,
            **args
          )
        end

        before do
          keystore_with.write("TEST")
        end

        it "does not check the group when none is supplied" do
          assert_equal "TEST", keystore_with.read
        end

        it "reads a key file belonging to the supplied group id" do
          assert_equal "TEST", keystore_with(group: the_group).read
        end

        it "reads a key file belonging to the supplied group name" do
          assert_equal "TEST", keystore_with(group: Etc.getgrgid(the_group).name).read
        end

        it "accepts any group in the list" do
          assert_equal "TEST", keystore_with(group: [the_group + 1, the_group]).read
        end

        it "raises an exception when it belongs to another group" do
          error = assert_raises(SymmetricEncryption::ConfigError) { keystore_with(group: the_group + 1).read }

          assert_includes error.message, "has the wrong group:"
          assert_includes error.message, "(#{the_group})"
        end
      end

      describe "#initialize with an invalid owner or group" do
        it "rejects an unknown user name" do
          error = assert_raises(SymmetricEncryption::ConfigError) do
            SymmetricEncryption::Keystore::File.new(key_filename: "tester.key", owner: "no_such_user_here")
          end

          assert_includes error.message, "There is no such owner on this machine"
        end

        it "rejects an unknown group name" do
          error = assert_raises(SymmetricEncryption::ConfigError) do
            SymmetricEncryption::Keystore::File.new(key_filename: "tester.key", group: "no_such_group_here")
          end

          assert_includes error.message, "There is no such group on this machine"
        end

        it "rejects a negative id" do
          assert_raises(SymmetricEncryption::ConfigError) do
            SymmetricEncryption::Keystore::File.new(key_filename: "tester.key", owner: -1)
          end
        end

        it "rejects a value that is neither a name nor an id" do
          assert_raises(SymmetricEncryption::ConfigError) do
            SymmetricEncryption::Keystore::File.new(key_filename: "tester.key", owner: :root)
          end
        end

        it "rejects an empty list" do
          assert_raises(SymmetricEncryption::ConfigError) do
            SymmetricEncryption::Keystore::File.new(key_filename: "tester.key", group: [])
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
            permissions: "0644",
            owner:       Etc.getpwuid(Process.uid).name
          )
        end

        it "survives a round trip through the config file" do
          config_file_name = "#{the_test_path}/symmetric-encryption.yml"
          SymmetricEncryption::Config.write_file(config_file_name, {test: {ciphers: [key_config]}})
          config = SymmetricEncryption::Config.read_file(config_file_name)[:test][:ciphers].first
          kekek_config = config[:key_encrypting_key][:key_encrypting_key]

          assert_equal "0644", config[:permissions]
          assert_equal Etc.getpwuid(Process.uid).name, config[:owner]
          assert_equal "0644", kekek_config[:permissions]
          assert_equal Etc.getpwuid(Process.uid).name, kekek_config[:owner]

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
