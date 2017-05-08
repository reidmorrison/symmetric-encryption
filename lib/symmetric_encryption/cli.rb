require 'optparse'
require 'fileutils'
require 'erb'

module SymmetricEncryption
  class CLI
    attr_reader :parser, :options, :key_path, :app_name

    def initialize(argv)
      @options = {}
      setup
      parser.parse!(argv.dup)
    end

    def run!
      if options[:encrypt] || options[:decrypt] || options[:random_password] || options[:keys]
        check_env_file_options
        load
      end

      if options[:encrypt]
        encrypt
      elsif options[:decrypt]
        decrypt
      elsif options[:random_password]
        random_password
      elsif options[:keys]
        generate_keys
      elsif options[:config]
        check_key_path_name_options
        @key_path = options[:key_path]
        @app_name = options[:name]
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

        opts.on '-e', '--encrypt', 'Encrypt a plain text value. Requires --env and --file.' do |encrypt|
          options[:encrypt] = encrypt
        end

        opts.on '-d', '--decrypt VALUE', 'Decrypt a encrypted value. Requires --env and --file.' do |decrypt|
          options[:decrypt] = decrypt
        end

        opts.on '-r', '--random', 'Generate a random password.' do |random|
          options[:random_password] = random
        end

        opts.on '-k', '--keys', 'Generate encryption keys Requires --env and --file.' do |keys|
          options[:keys] = keys
        end

        opts.on '-c', '--config', 'Generate a configuration file. Requires --path and --name' do |config|
          options[:config] = config
        end

        opts.on '-p', '--path KEY_PATH', 'Key path for configuration generator.' do |path|
          options[:key_path] = path
        end

        opts.on '-n', '--name NAME', 'Name for configuration generator' do |name|
          options[:name] = name
        end

        opts.on '-v', '--env ENVIRONMENT', 'Which environment are we using.' do |environment|
          options[:environment] = environment
        end

        opts.on '-f', '--file FILE_PATH', 'File path of your configuration file.' do |path|
          options[:file_path] = path
        end
      end
    end

    def generate_config
      template_path = File.expand_path('../../rails/generators/symmetric_encryption/config/templates', __FILE__)
      FileUtils.cp_r(template_path, 'config')

      template = File.join('config', 'symmetric-encryption.yml')
      file     = File.read(template)

      File.open(template, 'w') do |f|
        f << ERB.new(file, nil, '-').result(binding)
      end

      puts "New configuration at: #{File.expand_path(File.join('config', 'symmetric-encryption.yml'))}"
    end

    def generate_keys
      SymmetricEncryption.generate_symmetric_key_files(options[:file_path], options[:environment])
    end

    def decrypt
      puts "Decrypted: #{SymmetricEncryption.decrypt(options[:decrypt])}\n\n"
    end

    def random_password
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
      raise SymmetricEncryption::Error, 'Missing required --path option'  unless options[:key_path]
    end

    def check_name
      raise SymmetricEncryption::Error, 'Missing required --name option'  unless options[:name]
    end

    def check_env
      raise SymmetricEncryption::Error, 'Missing required --env option'  unless options[:environment]
    end

    def check_file
      raise SymmetricEncryption::Error, 'Missing required --file option' unless options[:file_path]
    end

    def load
      SymmetricEncryption.load!(options[:file_path], options[:environment])
    end
  end
end