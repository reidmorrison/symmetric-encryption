require "optparse"
require "fileutils"
module SymmetricEncryption
  class CLI
    attr_reader :key_path, :app_name, :encrypt, :config_file_path,
                :decrypt, :random_password, :new_keys, :generate, :environment,
                :keystore, :re_encrypt, :version, :output_file_name, :compress,
                :environments, :cipher_name, :rolling_deploy, :rotate_keys, :rotate_kek, :prompt, :show_version,
                :cleanup_keys, :activate_key, :migrate, :regions

    KEYSTORES = %i[aws heroku environment file gcp].freeze

    def self.run!(argv)
      new(argv).run!
    end

    def initialize(argv)
      @version          = current_version
      @environment      = ENV["SYMMETRIC_ENCRYPTION_ENV"] || ENV["RACK_ENV"] || ENV["RAILS_ENV"] || "development"
      @config_file_path = File.expand_path(ENV["SYMMETRIC_ENCRYPTION_CONFIG"] || "config/symmetric-encryption.yml")
      @app_name         = "symmetric-encryption"
      @key_path         = "#{ENV['HOME']}/.symmetric-encryption"
      @cipher_name      = "aes-256-cbc"
      @rolling_deploy   = false
      @prompt           = false
      @show_version     = false
      @keystore         = :file

      if argv.empty?
        puts parser
        exit(-10)
      end
      parser.parse!(argv)
    end

    def run!
      raise(ArgumentError, "Cannot cleanup keys and rotate keys at the same time") if cleanup_keys && rotate_keys

      if show_version
        puts "Symmetric Encryption v#{VERSION}"
        puts "OpenSSL v#{OpenSSL::VERSION}"
        puts "Environment: #{environment}"
      elsif encrypt
        load_config
        prompt ? encrypt_string : encrypt_file(encrypt)
      elsif decrypt
        load_config
        prompt ? decrypt_string : decrypt_file(decrypt)
      elsif random_password
        load_config
        gen_random_password(random_password)
      elsif migrate
        run_migrate
      elsif re_encrypt
        load_config
        SymmetricEncryption::Utils::ReEncryptFiles.new(version: version).process_directory(re_encrypt)
      elsif activate_key
        run_activate_key
      elsif rotate_kek
        run_rotate_kek
      elsif rotate_keys
        run_rotate_keys
      elsif cleanup_keys
        run_cleanup_keys
      elsif generate
        generate_new_config
      else
        puts parser
      end
    end

    def parser
      @parser ||= OptionParser.new do |opts|
        opts.banner = <<~BANNER
          Symmetric Encryption v#{VERSION}

            For more information, see: https://encryption.rocketjob.io/

            Note:
              It is recommended to backup the current configuration file, or place it in version control before running
              the configuration manipulation commands below.

          symmetric-encryption [options]
        BANNER

        opts.on "-e", "--encrypt [FILE_NAME]", "Encrypt a file, or read from stdin if no file name is supplied." do |file_name|
          @encrypt = file_name || STDIN
        end

        opts.on "-d", "--decrypt [FILE_NAME]", "Decrypt a file, or read from stdin if no file name is supplied." do |file_name|
          @decrypt = file_name || STDIN
        end

        opts.on "-o", "--output FILE_NAME",
                "Write encrypted or decrypted file to this file, otherwise output goes to stdout." do |file_name|
          @output_file_name = file_name
        end

        opts.on "-P", "--prompt", "When encrypting or decrypting, prompt for a string encrypt or decrypt." do
          @prompt = true
        end

        opts.on "-z", "--compress", "Compress encrypted output file. [Default for encrypting files]" do
          @compress = true
        end

        opts.on "-Z", "--no-compress", "Does not compress the output file. [Default for encrypting strings]" do
          @compress = false
        end

        opts.on "-E", "--env ENVIRONMENT",
                "Environment to use in the config file. Default: SYMMETRIC_ENCRYPTION_ENV || RACK_ENV || RAILS_ENV || 'development'" do |environment|
          @environment = environment
        end

        opts.on "-c", "--config CONFIG_FILE_PATH",
                "File name & path to the Symmetric Encryption configuration file. Default: config/symmetric-encryption.yml or Env var: `SYMMETRIC_ENCRYPTION_CONFIG`" do |path|
          @config_file_path = path
        end

        opts.on "-m", "--migrate", "Migrate configuration file to new format." do
          @migrate = true
        end

        opts.on "-r", "--re-encrypt [PATTERN]",
                'ReEncrypt all files matching the pattern. Default:  "**/*.{yml,rb}"' do |pattern|
          @re_encrypt = pattern || "**/*.{yml,rb}"
        end

        opts.on "-n", "--new-password [SIZE]",
                "Generate a new random password using only characters that are URL-safe base64. Default size is 22." do |size|
          @random_password = (size || 22).to_i
        end

        opts.on "-g", "--generate", "Generate a new configuration file and encryption keys for every environment." do |config|
          @generate = config
        end

        opts.on "-s", "--keystore heroku|environment|file|aws|gcp",
                "Which keystore to use during generation or re-encryption." do |keystore|
          @keystore = (keystore || "file").downcase.to_sym
        end

        opts.on "-B", "--regions [us-east-1,us-east-2,us-west-1,us-west-2]",
                "AWS KMS Regions to encrypt data key with." do |regions|
          @regions = regions.to_s.split(",").collect(&:strip) if regions
        end

        opts.on "-K", "--key-path KEY_PATH",
                "Output path in which to write generated key files. Default: ~/.symmetric-encryption" do |path|
          @key_path = path
        end

        opts.on "-a", "--app-name NAME",
                "Application name to use when generating a new configuration. Default: symmetric-encryption" do |name|
          @app_name = name
        end

        opts.on "-S", "--environments ENVIRONMENTS",
                "Comma separated list of environments for which to generate the config file. Default: development,test,release,production" do |environments|
          @environments = environments.split(",").collect(&:strip).collect(&:to_sym)
        end

        opts.on "-C", "--cipher-name NAME",
                "Name of the cipher to use when generating a new config file, or when rotating keys. Default: aes-256-cbc" do |name|
          @cipher_name = name
        end

        opts.on "-R", "--rotate-keys",
                "Generates a new encryption key version, encryption key files, and updates the configuration file." do
          @rotate_keys = true
        end

        opts.on "-U", "--rotate-kek",
                "Replace the existing key encrypting keys only, the data encryption key is not changed, and updates the configuration file." do
          @rotate_kek = true
        end

        opts.on "-D", "--rolling-deploy",
                "During key rotation, support a rolling deploy by placing the new key second in the list so that it is not activated yet." do
          @rolling_deploy = true
        end

        opts.on "-A", "--activate-key", "Activates the key by moving the key with the highest version to the top." do
          @activate_key = true
        end

        opts.on "-X", "--cleanup-keys",
                "Removes all encryption keys, except the one with the highest version from the configuration file." do
          @cleanup_keys = true
        end

        opts.on "-V", "--key-version NUMBER",
                "Encryption key version to use when encrypting or re-encrypting. Default: (Current global version)." do |number|
          @version = number.to_i
        end

        opts.on "-L", "--ciphers", "List available OpenSSL ciphers." do
          puts "OpenSSL v#{OpenSSL::VERSION}. Available Ciphers:"
          puts OpenSSL::Cipher.ciphers.join("\n")
          exit
        end

        opts.on "-v", "--version", "Display Symmetric Encryption version." do
          @show_version = true
        end

        opts.on("-h", "--help", "Prints this help.") do
          puts opts
          exit
        end
      end
    end

    private

    attr_writer :environments

    def load_config
      Config.load!(file_name: config_file_path, env: environment)
    end

    def generate_new_config
      unless KEYSTORES.include?(keystore)
        puts "Invalid keystore option: #{keystore}, must be one of #{KEYSTORES.join(', ')}"
        exit(-3)
      end

      config_file_does_not_exist!
      self.environments ||= %i[development test release production]
      args = {
        app_name:     app_name,
        environments: environments,
        cipher_name:  cipher_name
      }
      args[:key_path]   = key_path if key_path
      args[:regions]    = regions if regions && !regions.empty?
      cfg               = Keystore.generate_data_keys(keystore: keystore, **args)
      Config.write_file(config_file_path, cfg)
      puts "New configuration file created at: #{config_file_path}"
    end

    def run_migrate
      config = Config.read_file(config_file_path)
      Config.write_file(config_file_path, config)
      puts "Existing configuration file successfully migrated to the new format: #{config_file_path}"
    end

    def run_rotate_keys
      if keystore && !KEYSTORES.include?(keystore)
        puts "Invalid keystore option: #{keystore}, must be one of #{KEYSTORES.join(', ')}"
        exit(-3)
      end

      config = Config.read_file(config_file_path)
      SymmetricEncryption::Keystore.rotate_keys!(config, environments: environments || [], app_name: app_name,
rolling_deploy: rolling_deploy, keystore: keystore)
      Config.write_file(config_file_path, config)
      puts "Existing configuration file updated with new keys: #{config_file_path}"
    end

    def run_rotate_kek
      config = Config.read_file(config_file_path)
      SymmetricEncryption::Keystore.rotate_key_encrypting_keys!(config, environments: environments || [], app_name: app_name)
      Config.write_file(config_file_path, config)
      puts "Existing configuration file updated with new key encrypting keys: #{config_file_path}"
    end

    def run_cleanup_keys
      config = Config.read_file(config_file_path)
      config.each_pair do |env, cfg|
        next if environments && !environments.include?(env.to_sym)
        next unless ciphers = cfg[:ciphers]

        highest = ciphers.max_by { |i| i[:version] }
        ciphers.clear
        ciphers << highest
      end

      Config.write_file(config_file_path, config)
      puts "Removed all but the key with the highest version in: #{config_file_path}"
    end

    def run_activate_key
      config = Config.read_file(config_file_path)
      config.each_pair do |env, cfg|
        next if environments && !environments.include?(env.to_sym)
        next unless ciphers = cfg[:ciphers]

        highest = ciphers.max_by { |i| i[:version] }
        ciphers.delete(highest)
        ciphers.unshift(highest)
      end

      Config.write_file(config_file_path, config)
      puts "Activated the keys with the highest versions in: #{config_file_path}"
    end

    def encrypt_file(input_file_name)
      SymmetricEncryption::Writer.encrypt(source: input_file_name, target: output_file_name || STDOUT, compress: compress,
version: version)
    end

    def decrypt_file(input_file_name)
      SymmetricEncryption::Reader.decrypt(source: input_file_name, target: output_file_name || STDOUT, version: version)
    end

    def decrypt_string
      begin
        require "highline"
      rescue LoadError
        puts("\nPlease install gem highline before using the command line task to decrypt an entered string.\n   gem install \"highline\"\n\n")
        exit(-2)
      end

      encrypted = HighLine.new.ask("Enter the value to decrypt:")
      text      = SymmetricEncryption.cipher(version).decrypt(encrypted)

      puts("\n\nEncrypted: #{encrypted}")
      output_file_name ? File.open(output_file_name, "wb") { |f| f << text } : puts("Decrypted: #{text}\n\n")
    end

    def encrypt_string
      begin
        require "highline"
      rescue LoadError
        puts("\nPlease install gem highline before using the command line task to encrypt an entered string.\n   gem install \"highline\"\n\n")
        exit(-2)
      end
      value1 = nil
      value2 = 0

      while value1 != value2
        value1 = HighLine.new.ask("Enter the value to encrypt:") { |q| q.echo = "*" }
        value2 = HighLine.new.ask("Re-enter the value to encrypt:") { |q| q.echo = "*" }

        puts("Values do not match, please try again") if value1 != value2
      end
      compress  = false if compress.nil?
      encrypted = SymmetricEncryption.cipher(version).encrypt(value1, compress: compress)
      output_file_name ? File.open(output_file_name, "wb") { |f| f << encrypted } : puts("\n\nEncrypted: #{encrypted}\n\n")
    end

    def gen_random_password(size)
      p = SymmetricEncryption.random_password(size)
      puts("\nGenerated Password: #{p}")
      encrypted = SymmetricEncryption.encrypt(p)
      puts("Encrypted: #{encrypted}\n\n")
      File.open(output_file_name, "wb") { |f| f << encrypted } if output_file_name
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
      exit(-1)
    end
  end
end
