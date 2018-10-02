module SymmetricEncryption #:nodoc:
  class Railtie < Rails::Railtie #:nodoc:
    # Exposes Symmetric Encryption's configuration to the Rails application configuration.
    #
    # @example Set up configuration in the Rails app.
    #   module MyApplication
    #     class Application < Rails::Application
    #       config.symmetric_encryption.cipher = SymmetricEncryption::Cipher.new(
    #         key:    '1234567890ABCDEF',
    #         iv:     '1234567890ABCDEF',
    #         cipher_name: 'aes-128-cbc'
    #       )
    #     end
    #   end
    config.symmetric_encryption = ::SymmetricEncryption

    # Initialize Symmetry. This will look for a symmetry.yml in the config
    # directory and configure Symmetry appropriately.
    #
    # @example symmetric-encryption.yml
    #
    #   development:
    #     cipher_name: aes-128-cbc
    #     key:         1234567890ABCDEF
    #     iv:          1234567890ABCDEF
    #
    # Loaded before Active Record initializes since database.yml can have encrypted
    # passwords in it
    config.before_configuration do
      # Check if already configured
      unless ::SymmetricEncryption.cipher?
        app_name      = Rails::Application.subclasses.first.parent.to_s.underscore
        config_file   =
          if (env_var = ENV['SYMMETRIC_ENCRYPTION_CONFIG'])
            Pathname.new File.expand_path(env_var)
          else
            Rails.root.join('config', 'symmetric-encryption.yml')
          end
        if config_file.file?
          begin
            ::SymmetricEncryption::Config.load!(file_name: config_file, env: ENV['SYMMETRIC_ENCRYPTION_ENV'] || Rails.env)
          rescue ArgumentError => exc
            puts "\nSymmetric Encryption not able to read keys."
            puts "#{exc.class.name} #{exc.message}"
            puts "To generate a new config file and key files: symmetric-encryption --generate --app-name #{app_name}\n\n"
            raise(exc)
          end
        else
          puts "\nSymmetric Encryption config not found."
          puts "To generate a new config file and key files: symmetric-encryption --generate --app-name #{app_name}\n\n"
        end
      end
    end
  end
end
