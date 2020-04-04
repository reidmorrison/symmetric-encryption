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

    # Initialize Symmetric Encryption. This will look for a symmetric-encryption.yml in the config
    # directory and configure Symmetric Encryption appropriately.
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
        parent_method = Module.method_defined?(:module_parent) ? "module_parent" : "parent"
        app_name      = Rails::Application.subclasses.first.send(parent_method).to_s.underscore
        env_var       = ENV["SYMMETRIC_ENCRYPTION_CONFIG"]
        config_file   =
          if env_var
            Pathname.new(File.expand_path(env_var))
          else
            Rails.root.join("config", "symmetric-encryption.yml")
          end

        if config_file.file?
          begin
            ::SymmetricEncryption::Config.load!(file_name: config_file, env: ENV["SYMMETRIC_ENCRYPTION_ENV"] || Rails.env)
          rescue ArgumentError => e
            puts "\nSymmetric Encryption not able to read keys."
            puts "#{e.class.name} #{e.message}"
            puts "To generate a new config file and key files: symmetric-encryption --generate --app-name #{app_name}\n\n"
            raise(e)
          end
        end

      end
    end
  end
end
