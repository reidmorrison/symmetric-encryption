require 'optparse'
require 'fileutils'
require 'erb'

module SymmetricEncryption
  class CLI
    attr_reader :parser, :key_path, :app_name, :encrypt, :config_file_path,
                :decrypt, :random_password, :keys, :gen_config, :environment,
                :heroku, :re_encrypt, :version, :output_filename, :compress

    def initialize(argv)
      @version          = SymmetricEncyption.cipher.version
      @environment      = ENV['RACK_ENV'] || ENV['RAILS_ENV'] || 'development'
      @config_file_path = 'config/symmetric-encryption.yml'
      @app_name         = 'symmetric-encryption'
      @key_path         = '/etc/symmetric-encryption'

      setup
      parser.parse!(argv.dup)
    end

    def run!
      unless gen_config
        Config.load!(config_file_path, environment)
      end

      if encrypt
        encrypt == true ? encrypt_string : encrypt_file(encrypt)
      elsif decrypt
        decrypt == true ? decrypt_string : decrypt_file(decrypt)
      elsif random_password
        gen_random_password
      elsif keys
        SymmetricEncryption.generate_symmetric_key_files(config_file_path, envirsonment)
      elsif gen_config
        generator = SymmetricEncryption::Utils::Generate.new
        filename  = generator.config(
          heroku:   heroku,
          key_path: key_path,
          app_name: app_name,
          filename: config_file_path
        )
        puts "New configuration file created at: #{filename}"
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

        opts.on '-e', '--encrypt FILE_NAME', 'Encrypt a file, or prompt for a text value if no file name is supplied.' do |filename|
          @encrypt = filename || true
        end

        opts.on '-d', '--decrypt FILE_NAME', 'Decrypt a file, or prompt for an encrypted value if no file name is supplied.' do |filename|
          @decrypt = filename || true
        end

        opts.on '-o', '--output FILE_NAME', 'Write encrypted or decrypted file to this file.' do |filename|
          @output_filename = filename
        end

        opts.on '-Z', '--compress', 'Compress encrypted output file. Default: false' do
          @compress = true
        end

        opts.on '-P', '--password', 'Generate a random password.' do
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
        opts.on '-k', '--keys', 'Generate encryption key files listed in the config file for this environment.' do |keys|
          @keys = keys
        end

        opts.on '-g', '--generate', 'Generate a new configuration file.' do |config|
          @gen_config = config
        end

        opts.on '-h', '--heroku', 'Target Heroku when generating a new config file, or when creating news keys.' do
          @heroku = true
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

        opts.on '-c', '--config CONFIG_FILE_PATH', 'File name & path to the Symmetric Encryption configuration file. Default: config/symmetric-encryption.yml' do |path|
          @config_file_path = path
        end

        opts.on '-r', '--re-encrypt PATTERN', 'ReEncrypt all files matching the pattern. Default: "**/*.yml"' do |pattern|
          @re_encrypt = pattern || '**/*.yml'
        end

        opts.on '-v', '--version NUMBER', "Encryption key version to use when encrypting or re-encrypting. Default: Current: #{SymmetricEncyption.cipher.version}" do |number|
          @version = number
        end

      end
    end

    def generate_config
      path          = heroku ? 'heroku_config/templates' : 'config/templates'
      template_path = File.expand_path("../../rails/generators/symmetric_encryption/#{path}", __FILE__)
      FileUtils.cp_r(template_path, 'config')

      template = File.join('config', 'symmetric-encryption.yml')
      file     = File.read(template)

      File.open(template, 'w') do |f|
        f << ERB.new(file, nil, '-').result(binding)
      end

      puts "New configuration at: #{File.expand_path(File.join('config', 'symmetric-encryption.yml'))}"
    end

    def decrypt_string
      begin
        require 'highline'
      rescue LoadError
        raise(SymmetricEncryption::ConfigError, "Please install gem highline before using the command line task to encrypt an entered string.\n   gem install \"highline\"")
      end

      encrypted = HighLine.new.ask('Enter the value to decrypt:')
      text      = SymmetricEncryption.decrypt(value)

      puts "\nEncrypted: #{encrypted}"
      output_filename ? File.open(output_filename, 'wb') { |f| f << text } : puts "Decrypted: #{text}\n\n"
    end

    def decrypt_file(input_filename)
      if output_filename
        puts "\nDecrypting file: #{input_filename} and writing to: #{output_filename}\n\n"
        SymmetricEncryption::Reader.decrypt(source: input_filename, target: output_filename)
        puts "\n#{output_filename} now contains the decrypted contents of #{input_filename}\n\n"
      else
        # No output file, so decrypt to stdout with no other output.
        SymmetricEncryption::Reader.decrypt(source: input_filename, target: STDOUT)
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
          puts 'Values do not match, please try again'
        end
      end

      encrypted = SymmetricEncryption.encrypt(value1)
      output_filename ? File.open(output_filename, 'wb') { |f| f << encrypted } : puts "\nEncrypted: #{encrypted}\n\n"
    end

    def encrypt_file(input_filename)
      if output_filename
        puts "\nEncrypting file: #{input_filename} and writing to: #{output_filename}\n\n"
        SymmetricEncryption::Writer.encrypt(source: input_filename, target: output_filename, compress: compress)
        puts "\n#{output_filename} now contains the decrypted contents of #{input_filename}\n\n"
      else
        # No output file, so decrypt to stdout with no other output.
        SymmetricEncryption::Reader.decrypt(source: input_filename, target: STDOUT)
      end
    end

    def gen_random_password
      p = SymmetricEncryption.random_password
      puts "\nGenerated Password: #{p}"
      encrypted = SymmetricEncryption.encrypt(p)
      puts "Encrypted: #{encrypted}\n\n"
      File.open(output_filename, 'wb') { |f| f << encrypted } if output_filename
    end

  end
end
