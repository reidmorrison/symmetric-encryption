require 'optparse'
require 'fileutils'
require 'erb'

module SymmetricEncryption
  class CLI
    attr_reader :parser, :key_path, :app_name, :encrypt, :config_file_path,
                :decrypt, :random_password, :new_keys, :generate, :environment,
                :keystore, :re_encrypt, :version, :output_file_name, :compress,
                :environments, :cipher_name, :rolling_deploy, :rotate_keys, :prompt, :show_version

    KEYSTORES = [:heroku, :environment, :file]

    def self.run!(argv)
      new(argv).run!
    end

    def initialize(argv)
      @version          = current_version
      @environment      = ENV['RACK_ENV'] || ENV['RAILS_ENV'] || 'development'
      @config_file_path = 'config/symmetric-encryption.yml'
      @app_name         = 'symmetric-encryption'
      @key_path         = '/etc/symmetric-encryption'
      @cipher_name      = 'aes-256-cbc'
      @rolling_deploy   = false
      @prompt           = false
      @show_version     = false
      @environments     = %w(development test release production)

      parse_args(argv)
    end

    def run!
      Config.load!(file_name: config_file_path, env: environment) unless generate || rotate_keys || show_version

      if show_version
        puts "Symmetric Encryption v#{VERSION}"
        puts "OpenSSL v#{OpenSSL::VERSION}"
        puts "Environment: #{environment}"
      elsif encrypt
        prompt ? encrypt_string : encrypt_file(encrypt)
      elsif decrypt
        prompt ? decrypt_string : decrypt_file(decrypt)
      elsif random_password
        gen_random_password(random_password)
      elsif generate
        config_file_does_not_exist!
        cfg =
          if keystore == :file
            SymmetricEncryption::Keystore::Environment.new_config(
              app_name:     app_name,
              environments: environments,
              cipher_name:  cipher_name
            )
          elsif [:heroku, :environment].include?(keystore)
            SymmetricEncryption::Keystore::File.new_config(
              key_path:     key_path,
              app_name:     app_name,
              environments: environments,
              cipher_name:  cipher_name
            )
          else
            puts "Invalid keystore option: #{keystore}, must be one of #{KEYSTORES.join(', ')}"
            exit -3
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

    private

    def parse_args(argv)
      @parser = OptionParser.new do |opts|
        opts.banner = "Symmetric Encryption v#{VERSION}\n\n  For more information, see: https://rocketjob.github.io/symmetric-encryption/\n\nsymmetric-encryption [options]\n"

        opts.on '-e', '--encrypt [FILE_NAME]', 'Encrypt a file, or read from stdin if no file name is supplied.' do |file_name|
          @encrypt = file_name || STDIN
        end

        opts.on '-d', '--decrypt [FILE_NAME]', 'Decrypt a file, or read from stdin if no file name is supplied.' do |file_name|
          @decrypt = file_name || STDIN
        end

        opts.on '-o', '--output FILE_NAME', 'Write encrypted or decrypted file to this file, otherwise output goes to stdout.' do |file_name|
          @output_file_name = file_name
        end

        opts.on '-P', '--prompt', 'When encrypting or decrypting, prompt for a string encrypt or decrypt.' do
          @prompt = true
        end

        opts.on '-z', '--compress', 'Compress encrypted output file.' do
          @compress = true
        end

        opts.on '-E', '--env ENVIRONMENT', "Environment to use in the config file. Default: RACK_ENV || RAILS_ENV || 'development'" do |environment|
          @environment = environment
        end

        opts.on '-c', '--config CONFIG_FILE_PATH', 'File name & path to the Symmetric Encryption configuration file. Default: config/symmetric-encryption.yml' do |path|
          @config_file_path = path
        end

        opts.on '-r', '--re-encrypt PATTERN', 'ReEncrypt all files matching the pattern. Default: "**/*.yml"' do |pattern|
          @re_encrypt = pattern || '**/*.yml'
        end

        opts.on '-n', '--new-password [SIZE]', 'Generate a new random password using only characters that are URL-safe base64. Default size is 22.' do |size|
          @random_password = (size || 22).to_i
        end

        opts.on '-g', '--generate', 'Generate a new configuration file and encryption keys for every environment.' do |config|
          @generate = config
        end

        opts.on '-s', '--keystore [heroku|environment|file]', 'Generate a new configuration file and encryption keys for every environment.' do |keystore|
          @keystore = (keystore || 'file').downcase.to_sym
        end

        opts.on '-K', '--key-path KEY_PATH', 'Output path in which to write generated key files. Default: /etc/symmetric-encryption' do |path|
          @key_path = path
        end

        opts.on '-a', '--app-name NAME', 'Application name to use when generating a new configuration. Default: symmetric-encryption' do |name|
          @app_name = name
        end

        opts.on '-S', '--envs ENVIRONMENTS', "Comma separated list of environments for which to generate the config file. Default: development,test,release,production" do |environments|
          @environments = environments.split(',').collect(&:strip)
        end

        opts.on '-C', '--cipher-name NAME', "Name of the cipher to use when generating a new config file, or when rotating keys. Default: aes-256-cbc" do |name|
          @cipher_name = name
        end

        opts.on '-R', '--rotate-keys', 'Generates a new encryption key version, encryption key files, and updates symmetric-encryption.yml.' do
          @rotate_keys = true
        end

        opts.on '-D', '--rolling-deploy', 'During key rotation, support a rolling deploy by placing the new key second in the list so that it is not activated yet.' do
          @rolling_deploy = true
        end

        opts.on '-V', '--key-version NUMBER', "Encryption key version to use when encrypting or re-encrypting. Default: (Current global version)." do |number|
          @version = number
        end

        opts.on '-L', '--ciphers', 'List available OpenSSL ciphers.' do
          puts "OpenSSL v#{OpenSSL::VERSION}. Available Ciphers:"
          puts OpenSSL::Cipher.ciphers.join("\n")
          exit
        end

        opts.on '-v', '--version', 'Display Symmetric Encryption version.' do
          @show_version = true
        end

        opts.on('-h', '--help', 'Prints this help.') do
          puts opts
          exit
        end

      end
      parser.parse!(argv)
    end

    def encrypt_file(input_file_name)
      SymmetricEncryption::Writer.encrypt(source: input_file_name, target: output_file_name || STDOUT, compress: compress, version: version)
    end

    def decrypt_file(input_file_name)
      SymmetricEncryption::Reader.decrypt(source: input_file_name, target: output_file_name || STDOUT, version: version)
    end

    def decrypt_string
      begin
        require 'highline'
      rescue LoadError
        puts("\nPlease install gem highline before using the command line task to decrypt an entered string.\n   gem install \"highline\"\n\n")
        exit -2
      end

      encrypted = HighLine.new.ask('Enter the value to decrypt:')
      text      = SymmetricEncryption.cipher(version).decrypt(encrypted)

      puts("\nEncrypted: #{encrypted}")
      output_file_name ? File.open(output_file_name, 'wb') { |f| f << text } : puts("Decrypted: #{text}\n\n")
    end

    def encrypt_string
      begin
        require 'highline'
      rescue LoadError
        puts("\nPlease install gem highline before using the command line task to encrypt an entered string.\n   gem install \"highline\"\n\n")
        exit -2
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

      encrypted = SymmetricEncryption.cipher(version).encrypt(value1)
      output_file_name ? File.open(output_file_name, 'wb') { |f| f << encrypted } : puts("\nEncrypted: #{encrypted}\n\n")
    end

    def gen_random_password(size)
      p = SymmetricEncryption.random_password(size)
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
      return unless File.exist?(config_file_path)
      puts "\nConfiguration file already exists, please move or rename: #{config_file_path}\n\n"
      exit -1
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
