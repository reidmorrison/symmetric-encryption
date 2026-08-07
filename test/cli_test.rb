require_relative "test_helper"

module SymmetricEncryption
  class CLITest < Minitest::Test
    describe SymmetricEncryption::CLI do
      let :the_test_path do
        "tmp/cli_test"
      end

      let :config_file_name do
        "#{the_test_path}/symmetric-encryption.yml"
      end

      # The config file shipped with the test suite, used by the actions that load a config.
      let :the_config_file_name do
        File.join(File.dirname(__FILE__), "config", "symmetric-encryption.yml")
      end

      before do
        FileUtils.rm_rf(the_test_path)
        FileUtils.makedirs(the_test_path)

        # The CLI loads config files, which replaces the ciphers loaded by test_helper.
        @cipher            = SymmetricEncryption.cipher
        @secondary_ciphers = SymmetricEncryption.secondary_ciphers
      end

      after do
        SymmetricEncryption.cipher            = @cipher
        SymmetricEncryption.secondary_ciphers = @secondary_ciphers
        FileUtils.rm_rf(the_test_path)
      end

      # Generates a new config file with keys for the supplied environments.
      def generate_config(*environments)
        environments = %i[test preprod production] if environments.empty?
        capture_io do
          CLI.new(
            %W[--generate
               --config #{config_file_name}
               --key-path #{the_test_path}
               --app-name tester
               --environments #{environments.join(',')}]
          ).run!
        end
      end

      def versions_for(environment)
        Config.read_file(config_file_name)[environment][:ciphers].collect { |c| c[:version] }
      end

      describe "#initialize" do
        it "displays the help and exits when no arguments are supplied" do
          out, = capture_io do
            assert_raises(SystemExit) { CLI.new([]) }
          end
          assert_includes out, "symmetric-encryption [options]"
        end

        it "defaults" do
          cli = CLI.new(%w[--generate])
          assert_equal "symmetric-encryption", cli.app_name
          assert_equal "aes-256-cbc", cli.cipher_name
          assert_equal :file, cli.keystore
          assert_equal "#{Dir.home}/.symmetric-encryption", cli.key_path
          refute cli.rolling_deploy
          refute cli.prompt
          refute cli.show_version
        end

        it "parses the file and path options" do
          cli = CLI.new(%w[--encrypt in.txt --output out.txt --config cfg.yml --key-path /tmp/keys --app-name my_app])
          assert_equal "in.txt", cli.encrypt
          assert_equal "out.txt", cli.output_file_name
          assert_equal "cfg.yml", cli.config_file_path
          assert_equal "/tmp/keys", cli.key_path
          assert_equal "my_app", cli.app_name
        end

        it "reads from stdin when no file name is supplied to encrypt or decrypt" do
          assert_equal $stdin, CLI.new(%w[--encrypt]).encrypt
          assert_equal $stdin, CLI.new(%w[--decrypt]).decrypt
        end

        it "parses the key rotation options" do
          cli = CLI.new(%w[--rotate-keys --rolling-deploy --environments preprod,production --cipher-name aes-128-cbc])
          assert cli.rotate_keys
          assert cli.rolling_deploy
          assert_equal "aes-128-cbc", cli.cipher_name
          assert_equal %i[preprod production], cli.send(:environments)
        end

        it "parses the remaining flags" do
          assert CLI.new(%w[--migrate]).migrate
          assert CLI.new(%w[--rotate-kek]).rotate_kek
          assert CLI.new(%w[--activate-key]).activate_key
          assert CLI.new(%w[--cleanup-keys]).cleanup_keys
          assert CLI.new(%w[--version]).show_version
          assert CLI.new(%w[--prompt]).prompt
          assert CLI.new(%w[--compress]).compress
          refute CLI.new(%w[--no-compress]).compress
          assert_equal 3, CLI.new(%w[--key-version 3]).version
          assert_equal "preprod", CLI.new(%w[--env preprod]).environment
          assert_equal :heroku, CLI.new(%w[--keystore heroku]).keystore
          assert_equal %w[us-east-1 us-west-2], CLI.new(["--regions", "us-east-1, us-west-2"]).regions
        end

        it "defaults the re-encrypt pattern" do
          assert_equal "**/*.{yml,rb}", CLI.new(%w[--re-encrypt]).re_encrypt
          assert_equal "**/*.yml", CLI.new(%w[--re-encrypt **/*.yml]).re_encrypt
        end

        it "defaults the new password size" do
          assert_equal 22, CLI.new(%w[--new-password]).random_password
          assert_equal 8, CLI.new(%w[--new-password 8]).random_password
        end
      end

      describe "#run!" do
        it "displays the version" do
          out, = capture_io { CLI.new(%w[--version]).run! }
          assert_includes out, "Symmetric Encryption v#{VERSION}"
          assert_includes out, "OpenSSL v#{OpenSSL::VERSION}"
        end

        it "displays the help when no action is supplied" do
          out, = capture_io { CLI.new(%w[--compress]).run! }
          assert_includes out, "symmetric-encryption [options]"
        end

        it "refuses to cleanup and rotate keys at the same time" do
          cli = CLI.new(%w[--cleanup-keys --rotate-keys])
          assert_raises(ArgumentError) { cli.run! }
        end
      end

      describe "--generate" do
        it "creates a config file with a key file per environment" do
          generate_config(:test, :preprod, :production)

          assert File.exist?(config_file_name)
          config = Config.read_file(config_file_name)
          assert_equal %i[test preprod production], config.keys

          # development and test share the well known development keys.
          assert_equal Keystore.dev_config, config[:test]

          %i[preprod production].each do |env|
            cipher = config[env][:ciphers].first
            assert_equal 1, cipher[:version]
            assert File.exist?(cipher[:key_filename]), "Missing key file for #{env}"
          end
        end

        it "does not overwrite an existing config file" do
          generate_config
          out, = capture_io do
            assert_raises(SystemExit) do
              CLI.new(%W[--generate --config #{config_file_name} --key-path #{the_test_path}]).run!
            end
          end
          assert_includes out, "Configuration file already exists"
        end

        it "rejects an unknown keystore" do
          out, = capture_io do
            assert_raises(SystemExit) do
              CLI.new(%W[--generate --keystore bad --config #{config_file_name}]).run!
            end
          end
          assert_includes out, "Invalid keystore option: bad"
        end
      end

      describe "--rotate-keys" do
        it "adds a new active key version" do
          generate_config
          capture_io do
            CLI.new(%W[--rotate-keys --config #{config_file_name} --app-name tester]).run!
          end

          # The new key is first so that it is used immediately.
          assert_equal [2, 1], versions_for(:production)
        end

        it "adds the new key second during a rolling deploy" do
          generate_config
          capture_io do
            CLI.new(%W[--rotate-keys --rolling-deploy --config #{config_file_name} --app-name tester]).run!
          end

          # The new key is readable, but not yet used for encrypting.
          assert_equal [1, 2], versions_for(:production)
        end

        it "only rotates the supplied environments" do
          generate_config
          capture_io do
            CLI.new(%W[--rotate-keys --environments production --config #{config_file_name} --app-name tester]).run!
          end

          assert_equal [2, 1], versions_for(:production)
          assert_equal [1], versions_for(:preprod)
        end

        it "rejects an unknown keystore" do
          generate_config
          out, = capture_io do
            assert_raises(SystemExit) do
              CLI.new(%W[--rotate-keys --keystore bad --config #{config_file_name}]).run!
            end
          end
          assert_includes out, "Invalid keystore option: bad"
        end
      end

      describe "--rotate-kek" do
        it "replaces the key encrypting key without changing the data encrypting key" do
          generate_config

          before_config = Config.read_file(config_file_name)[:production][:ciphers].first
          before_key    = Keystore.read_key(**Marshal.load(Marshal.dump(before_config)).except(:always_add_header, :encoding))

          capture_io do
            CLI.new(%W[--rotate-kek --config #{config_file_name} --app-name tester]).run!
          end

          after_config = Config.read_file(config_file_name)[:production][:ciphers].first
          after_key    = Keystore.read_key(**after_config.except(:always_add_header, :encoding))

          # Same data encrypting key, so previously encrypted data is still readable.
          assert_equal before_key.key, after_key.key
          # Secured by a new key encrypting key.
          refute_equal before_config[:key_encrypting_key], after_config[:key_encrypting_key]
          # The version is unchanged, only one cipher remains.
          assert_equal [1], versions_for(:production)
        end
      end

      describe "--activate-key" do
        it "moves the highest version to the front" do
          generate_config
          capture_io do
            CLI.new(%W[--rotate-keys --rolling-deploy --config #{config_file_name} --app-name tester]).run!
          end
          assert_equal [1, 2], versions_for(:production)

          capture_io { CLI.new(%W[--activate-key --config #{config_file_name}]).run! }
          assert_equal [2, 1], versions_for(:production)
        end
      end

      describe "--cleanup-keys" do
        it "keeps only the highest version" do
          generate_config
          capture_io do
            CLI.new(%W[--rotate-keys --config #{config_file_name} --app-name tester]).run!
          end
          assert_equal [2, 1], versions_for(:production)

          capture_io { CLI.new(%W[--cleanup-keys --config #{config_file_name}]).run! }
          assert_equal [2], versions_for(:production)
        end
      end

      describe "--migrate" do
        it "rewrites the config file in the new format" do
          File.write(config_file_name, <<~CONFIG)
            production:
              cipher: aes-256-cbc
              key: ABCDEF1234567890ABCDEF1234567890
              iv: ABCDEF1234567890
          CONFIG

          out, = capture_io { CLI.new(%W[--migrate --config #{config_file_name}]).run! }
          assert_includes out, "successfully migrated"

          config = Config.read_file(config_file_name)
          cipher = config[:production][:ciphers].first
          # The inline cipher is moved under :ciphers and :cipher renamed to :cipher_name.
          assert_equal "aes-256-cbc", cipher[:cipher_name]
          assert_nil cipher[:cipher]
        end
      end

      describe "--new-password" do
        it "generates and encrypts a new password" do
          out, = capture_io do
            CLI.new(%W[--new-password 8 --config #{the_config_file_name} --env test]).run!
          end
          assert_includes out, "Generated Password:"
          assert_includes out, "Encrypted:"
        end

        it "writes the encrypted password to the output file" do
          output_file_name = "#{the_test_path}/password.txt"
          capture_io do
            CLI.new(%W[--new-password 8 --output #{output_file_name} --config #{the_config_file_name} --env test]).run!
          end

          assert File.exist?(output_file_name)
          refute_nil SymmetricEncryption.decrypt(File.read(output_file_name))
        end
      end

      describe "--encrypt and --decrypt" do
        let :source_file_name do
          "#{the_test_path}/source.txt"
        end

        let :encrypted_file_name do
          "#{the_test_path}/encrypted.dat"
        end

        let :decrypted_file_name do
          "#{the_test_path}/decrypted.txt"
        end

        it "round trips a file" do
          File.write(source_file_name, "Hello World\nSecond Line\n")

          capture_io do
            CLI.new(
              %W[--encrypt #{source_file_name} --output #{encrypted_file_name} --config #{the_config_file_name} --env test]
            ).run!
          end
          refute_includes File.binread(encrypted_file_name), "Hello World"

          capture_io do
            CLI.new(
              %W[--decrypt #{encrypted_file_name} --output #{decrypted_file_name} --config #{the_config_file_name} --env test]
            ).run!
          end
          assert_equal "Hello World\nSecond Line\n", File.read(decrypted_file_name)
        end
      end

      describe ".run!" do
        it "runs the supplied arguments" do
          out, = capture_io { CLI.run!(%w[--version]) }

          assert_includes out, "Symmetric Encryption v#{VERSION}"
        end
      end

      describe "--ciphers" do
        it "lists the available OpenSSL ciphers and exits" do
          out, = capture_io do
            assert_raises(SystemExit) { CLI.new(%w[--ciphers]) }
          end

          assert_includes out, "Available Ciphers:"
          assert_includes out, "aes-256-cbc"
        end
      end

      describe "--help" do
        it "displays the help and exits" do
          out, = capture_io do
            assert_raises(SystemExit) { CLI.new(%w[--help]) }
          end

          assert_includes out, "--rotate-keys"
        end
      end

      describe "--prompt" do
        let :the_value do
          "Hello World"
        end

        before do
          require "highline"
        end

        it "encrypts an entered value" do
          out, = capture_io do
            HighLine.stub_any_instance(:ask, the_value) do
              CLI.new(%W[--encrypt --prompt --config #{the_config_file_name} --env test]).run!
            end
          end

          assert_includes out, "Encrypted:"
          encrypted = out.split("Encrypted:").last.strip
          assert_equal the_value, SymmetricEncryption.decrypt(encrypted)
        end

        it "writes the encrypted value to the output file" do
          output_file_name = "#{the_test_path}/encrypted.txt"
          capture_io do
            HighLine.stub_any_instance(:ask, the_value) do
              CLI.new(%W[--encrypt --prompt --output #{output_file_name} --config #{the_config_file_name} --env test]).run!
            end
          end

          assert_equal the_value, SymmetricEncryption.decrypt(File.read(output_file_name))
        end

        it "decrypts an entered value" do
          SymmetricEncryption.load!(the_config_file_name, "test")
          encrypted = SymmetricEncryption.encrypt(the_value)

          out, = capture_io do
            HighLine.stub_any_instance(:ask, encrypted) do
              CLI.new(%W[--decrypt --prompt --config #{the_config_file_name} --env test]).run!
            end
          end

          assert_includes out, "Decrypted: #{the_value}"
        end

        it "writes the decrypted value to the output file" do
          SymmetricEncryption.load!(the_config_file_name, "test")
          encrypted        = SymmetricEncryption.encrypt(the_value)
          output_file_name = "#{the_test_path}/decrypted.txt"

          capture_io do
            HighLine.stub_any_instance(:ask, encrypted) do
              CLI.new(%W[--decrypt --prompt --output #{output_file_name} --config #{the_config_file_name} --env test]).run!
            end
          end

          assert_equal the_value, File.read(output_file_name)
        end
      end

      describe "without a configured cipher" do
        it "leaves the key version unset" do
          previous                   = SymmetricEncryption.cipher
          SymmetricEncryption.cipher = nil

          assert_nil CLI.new(%w[--generate]).version
        ensure
          SymmetricEncryption.cipher = previous
        end
      end

      describe "--re-encrypt" do
        it "re-encrypts encrypted values found in files" do
          SymmetricEncryption.load!(the_config_file_name, "test")
          # Encrypt with an older cipher version so that it has to be re-encrypted.
          encrypted = SymmetricEncryption.cipher(6).encrypt("Hello World")
          file_name = "#{the_test_path}/application.yml"
          File.write(file_name, "password: #{encrypted}\n")

          capture_io do
            CLI.new(%W[--re-encrypt #{the_test_path}/*.yml --config #{the_config_file_name} --env test]).run!
          end

          new_value = File.read(file_name).split(": ").last.strip
          refute_equal encrypted, new_value
          assert_equal "Hello World", SymmetricEncryption.decrypt(new_value)
        end
      end
    end
  end
end
