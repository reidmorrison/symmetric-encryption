require 'optparse'
require 'fileutils'
require 'erb'

module SymmetricEncryption
  class CLI
    attr_reader :parser, :key_path, :app_name, :encrypt, :config_file_path,
                :decrypt, :random_password, :new_keys, :gen_config, :environment,
                :env_var, :re_encrypt, :version, :output_file_name, :compress,
                :environments, :cipher_name, :rolling_deploy, :rotate_keys

    def initialize(argv)
      @version          = current_version
      @environment      = ENV['RACK_ENV'] || ENV['RAILS_ENV'] || 'development'
      @config_file_path = 'config/symmetric-encryption.yml'
      @app_name         = 'symmetric-encryption'
      @key_path         = '/etc/symmetric-encryption'
      @cipher_name      = 'aes-256-cbc'
      @rolling_deploy   = false

      setup
      parser.parse!(argv.dup)
    end

    def run!
      Config.load!(file_name: config_file_path, env: environment) unless gen_config || rotate_keys

      if encrypt
        encrypt == true ? encrypt_string : encrypt_file(encrypt)
      elsif decrypt
        decrypt == true ? decrypt_string : decrypt_file(decrypt)
      elsif random_password
        gen_random_password
      elsif gen_config
        config_file_does_not_exist!
        environments ||= %w(development test release production)
        cfg          =
          if env_var
            SymmetricEncryption::Keystore::Environment.new_config(
              app_name:     app_name,
              environments: environments,
              cipher_name:  cipher_name
            )
          else
            SymmetricEncryption::Keystore::File.new_config(
              key_path:     key_path,
              app_name:     app_name,
              environments: environments,
              cipher_name:  cipher_name
            )
          end
        save_config(cfg)
        puts "New configuration file created at: #{config_file_path}"
      elsif rotate_keys
        config = YAML.load(ERB.new(File.new(config_file_path).read).result)
        SymmetricEncryption::Config.send(:deep_symbolize_keys, config)

        cfg = SymmetricEncryption::Keystore.rotate_keys(config, environments: environments || [], app_name: app_name, rolling_deploy: rolling_deploy)

        save_config(cfg)
        puts "Existing configuration file updated with new keys: #{config_file_path}"
      elsif re_encrypt
        SymmetricEncryption::Utils::ReEncrypt.new(version: version).process_directory(re_encrypt)
      else
        puts parser
      end
    end

    def self.run!(argv)
      new(argv).run!
    end

    private

    def setup
      @parser = OptionParser.new do |opts|
        opts.banner = "Symmetric Encryption #{VERSION} CLI\n\nsymmetric-encryption <options>\n"

        opts.on '-e', '--encrypt FILE_NAME', 'Encrypt a file, or prompt for a text value if no file name is supplied.' do |file_name|
          @encrypt = file_name || true
        end

        opts.on '-d', '--decrypt FILE_NAME', 'Decrypt a file, or prompt for an encrypted value if no file name is supplied.' do |file_name|
          @decrypt = file_name || true
        end

        opts.on '-o', '--output FILE_NAME', 'Write encrypted or decrypted file to this file.' do |file_name|
          @output_file_name = file_name
        end

        opts.on '-Z', '--compress', 'Compress encrypted output file. Default: false' do
          @compress = true
        end

        opts.on '-P', '--password', 'Generate a random password.' do
          @random_password = true
        end

        opts.on '-r', '--rotate-keys', 'Generates a new encryption key version, encryption key files, and updates symmetric-encryption.yml.' do
          @rotate_keys = true
        end

        opts.on '-r', '--rolling_deploy', 'During key rotation, support a rolling deploy by placing the new key second in the list so that it is not activated yet.' do
          @rolling_deploy = true
        end

        opts.on '-g', '--generate', 'Generate a new configuration file and encryption keys for every environment.' do |config|
          @gen_config = config
        end

        opts.on '-h', '--heroku', 'Target Heroku when generating a new config file, or when creating news keys.' do
          @env_var = true
        end

        opts.on '-E', '--environment-vars', 'Store the encrypted key in an environment variable when generating a new config file.' do
          @env_var = true
        end

        opts.on '-K', '--key-path KEY_PATH', 'Output path in which to write generated key files. Default: /etc/symmetric-encryption' do |path|
          @key_path = path
        end

        opts.on '-a', '--app-name NAME', 'Application name to use in the configuration generator. Default: symmetric-encryption' do |name|
          @app_name = name
        end

        opts.on '-v', '--env ENVIRONMENT', "Environment to use in the config file. Default: RACK_ENV || RAILS_ENV || 'development'" do |environment|
          @environment = environment
        end

        opts.on '-V', '--envs ENVIRONMENTS', "Comma separated list of environments for which to generate the config file. Default: development,test,release,production" do |environments|
          @environments = environments.split(',').collect(&:strip)
        end

        opts.on '-c', '--config CONFIG_FILE_PATH', 'File name & path to the Symmetric Encryption configuration file. Default: config/symmetric-encryption.yml' do |path|
          @config_file_path = path
        end

        opts.on '-r', '--re-encrypt PATTERN', 'ReEncrypt all files matching the pattern. Default: "**/*.yml"' do |pattern|
          @re_encrypt = pattern || '**/*.yml'
        end

        opts.on '-v', '--version NUMBER', "Encryption key version to use when encrypting or re-encrypting. Default: Current: #{current_version}" do |number|
          @version = number
        end

        opts.on '-C', '--cipher-name NAME', "Name of the cipher to use when generating a new config file, or when rotating keys. Default: aes-256-cbc" do |name|
          @cipher_name = name
        end

      end
    end

    def decrypt_string
      begin
        require 'highline'
      rescue LoadError
        raise(SymmetricEncryption::ConfigError, "Please install gem highline before using the command line task to encrypt an entered string.\n   gem install \"highline\"")
      end

      encrypted = HighLine.new.ask('Enter the value to decrypt:')
      text      = SymmetricEncryption.decrypt(value)

      puts("\nEncrypted: #{encrypted}")
      output_file_name ? File.open(output_file_name, 'wb') { |f| f << text } : puts("Decrypted: #{text}\n\n")
    end

    def decrypt_file(input_file_name)
      if output_file_name
        puts("\nDecrypting file: #{input_file_name} and writing to: #{output_file_name}\n\n")
        SymmetricEncryption::Reader.decrypt(source: input_file_name, target: output_file_name)
        puts("\n#{output_file_name} now contains the decrypted contents of #{input_file_name}\n\n")
      else
        # No output file, so decrypt to stdout with no other output.
        SymmetricEncryption::Reader.decrypt(source: input_file_name, target: STDOUT)
      end
    end

    def encrypt_string
      begin
        require 'highline'
      rescue LoadError
        raise(SymmetricEncryption::ConfigError, "Please install gem highline before using the command line task to encrypt an entered string.\n   gem install \"highline\"")
      end
      value1 = nil
      value2 = 0

      while value1 != value2
        value1 = HighLine.new.ask('Enter the value to encrypt:') { |q| q.echo = '*' }
        value2 = HighLine.new.ask('Re-enter the value to encrypt:') { |q| q.echo = '*' }

        if value1 != value2
          puts('Values do not match, please try again')
        end
      end

      encrypted = SymmetricEncryption.encrypt(value1)
      output_file_name ? File.open(output_file_name, 'wb') { |f| f << encrypted } : puts("\nEncrypted: #{encrypted}\n\n")
    end

    def encrypt_file(input_file_name)
      if output_file_name
        puts("\nEncrypting file: #{input_file_name} and writing to: #{output_file_name}\n\n")
        SymmetricEncryption::Writer.encrypt(source: input_file_name, target: output_file_name, compress: compress)
        puts("\n#{output_file_name} now contains the decrypted contents of #{input_file_name}\n\n")
      else
        # No output file, so encrypt to stdout with no other output.
        SymmetricEncryption::Writer.encrypt(source: input_file_name, target: STDOUT)
      end
    end

    def gen_random_password
      p = SymmetricEncryption.random_password
      puts("\nGenerated Password: #{p}")
      encrypted = SymmetricEncryption.encrypt(p)
      puts("Encrypted: #{encrypted}\n\n")
      File.open(output_file_name, 'wb') { |f| f << encrypted } if output_file_name
    end

    def current_version
      SymmetricEncryption.cipher.version
    rescue SymmetricEncryption::ConfigError
      nil
    end

    # Ensure that the config file does not already exist before generating a new one.
    def config_file_does_not_exist!
      raise "Configuration file already exists, please move or delete: #{config_file_path}" if File.exist?(config_file_path)
    end

    def save_config(config)
      File.open(config_file_path, 'w') do |f|
        f.puts '# This file was auto generated by symmetric-encryption.'
        f.puts '# Recommend using symmetric-encryption to make changes.'
        f.puts '# For more info, run:'
        f.puts '#   symmetric-encryption --help'
        f.puts '#'
        f.write(config.to_yaml)
      end
    end

  end
end
