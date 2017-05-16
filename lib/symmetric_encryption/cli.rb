require 'optparse'
require 'fileutils'
require 'erb'

module SymmetricEncryption
  class CLI
    attr_reader :parser, :key_path, :app_name, :encrypt_value, :config_file_path,
                :decrypt_value, :random_password, :keys, :gen_config, :environment,
                :heroku

    def initialize(argv)
      setup
      parser.parse!(argv.dup)
    end

    def run!
      if encrypt_value || decrypt_value || random_password || keys
        check_env_file_options
        load
      end

      if encrypt_value
        encrypt
      elsif decrypt_value
        decrypt
      elsif random_password
        gen_random_password
      elsif keys
        generate_keys
      elsif gen_config
        check_key_path_name_options
        generate_config
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

        opts.on '-e', '--encrypt FILE_NAME', 'Encrypt a file, or a plain text value if no file name is supplied. Requires --env and --config.' do |file_name|
          @encrypt_value = file_name
        end

        opts.on '-d', '--decrypt FILE_NAME', 'Decrypt a file, or prompt for an encrypted value if no file name is supplied. Requires --env and --config.' do |file_name|
          @decrypt_value = file_name
        end

        opts.on '-r', '--random', 'Generate a random password.' do
          @random_password = true
        end

        # Generate new random symmetric keys for use with this Encryption library
        #
        # Note: Only the current Encryption key settings are used
        #
        # Creates Symmetric Key .key and initialization vector .iv
        # which is encrypted with the key encryption key.
        #
        # Existing key files will be renamed if present
        opts.on '-k', '--keys', 'Generate encryption keys Requires --env and --config.' do |keys|
          @keys = keys
        end

        opts.on '-g', '--generate', 'Generate a new configuration file. Requires --path and --name' do |config|
          @gen_config = config
        end

        opts.on '-h', '--heroku', 'Support Heroku when generating a new config file, or when creating news keys.' do
          @heroku = true
        end

        opts.on '-p', '--path KEY_PATH', 'Root path in which to generate key files when generating a new config file.' do |path|
          @key_path = path
        end

        # By default all encrypted key file names
        opts.on '-n', '--name NAME', 'Name for configuration generator' do |name|
          @app_name = name
        end

        opts.on '-v', '--env ENVIRONMENT', "Which environment are we using. Default: RACK_ENV || RAILS_ENV || 'development'" do |environment|
          @environment = environment || ENV['RACK_ENV'] || ENV['RAILS_ENV'] || 'development'
        end

        opts.on '-c', '--config CONFIG_FILE_PATH', 'File name & path to the Symmetric Encryption configuration file. Default: config/symmetric-encryption.yml' do |path|
          @config_file_path = path || 'config/symmetric-encryption.yml'
        end

        # Encrypt / Decrypt files

        # ReEncrypt files
        #
        #   If a file is encrypted, it is reencrypted with the cipher that has the highest version number.
        #   A file is already encrypted with the highest version is not reencrypted.
        #
        #   If a file is not encrypted, the file is searched for any encrypted values, and those values are reencrypted.
        #
        #   symmetric_encryption --reencrypt "**/*.yml"
        opts.on '-r', '--reencrypt PATTERN', 'ReEncrypt all files matching the pattern with the encryption key with the highest version number.' do |pattern|
          @re_encrypt = pattern || '**/*.yml'
        end

      end
    end

    def generate_config
      path = heroku ? 'heroku_config/templates' : 'config/templates'
      template_path = File.expand_path("../../rails/generators/symmetric_encryption/#{path}", __FILE__)
      FileUtils.cp_r(template_path, 'config')

      template = File.join('config', 'symmetric-encryption.yml')
      file     = File.read(template)

      File.open(template, 'w') do |f|
        f << ERB.new(file, nil, '-').result(binding)
      end

      puts "New configuration at: #{File.expand_path(File.join('config', 'symmetric-encryption.yml'))}"
    end

    def generate_keys
      SymmetricEncryption.generate_symmetric_key_files(config_file_path, environment)
    end

    def decrypt
      puts "Decrypted: #{SymmetricEncryption.decrypt(decrypt_value)}\n\n"
    end

    def gen_random_password
      p = SymmetricEncryption.random_password
      puts "\nGenerated Password: #{p}"
      puts "Encrypted: #{SymmetricEncryption.encrypt(p)}\n\n"
    end

    def encrypt
      begin
        require 'highline'
      rescue LoadError
        raise(SymmetricEncryption::ConfigError, "Please install gem highline before using the command line task to encrypt an entered string.\n   gem install \"highline\"")
      end
      password1 = nil
      password2 = 0

      while password1 != password2
        password1 = HighLine.new.ask('Enter the value to encrypt:') { |q| q.echo = '*' }
        password2 = HighLine.new.ask('Re-enter the value to encrypt:') { |q| q.echo = '*' }

        if password1 != password2
          puts 'Passwords do not match, please try again'
        end
      end

      puts "\nEncrypted: #{SymmetricEncryption.encrypt(password1)}\n\n"
    end

    def check_env_file_options
      check_env
      check_file
    end

    def check_key_path_name_options
      check_key_path
      check_name
    end

    def check_key_path
      raise SymmetricEncryption::Error, 'Missing required --path option' unless key_path
    end

    def check_name
      raise SymmetricEncryption::Error, 'Missing required --name option' unless app_name
    end

    def check_env
      raise SymmetricEncryption::Error, 'Missing required --env option' unless environment
    end

    def check_file
      raise SymmetricEncryption::Error, 'Missing required --config option' unless config_file_path
    end

    def load
      SymmetricEncryption.load!(config_file_path, environment)
    end
  end
end
