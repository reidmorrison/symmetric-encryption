module SymmetricEncryption # :nodoc:
  class Railtie < Rails::Railtie # :nodoc:
    # Exposes Symmetric Encryption's configuration to the Rails application configuration.
    #
    # `config.symmetric_encryption` is the SymmetricEncryption module itself, so anything it
    # exposes can be set from the Rails application configuration.
    #
    # @example Set up configuration in the Rails app.
    #   module MyApplication
    #     class Application < Rails::Application
    #       # Do not add encrypted attributes to the model's `filter_attributes`.
    #       config.symmetric_encryption.filter_encrypted_attributes = false
    #
    #       # Encrypt with a random iv by default.
    #       config.symmetric_encryption.randomize_iv = true
    #     end
    #   end
    config.symmetric_encryption = ::SymmetricEncryption

    # Initialize Symmetric Encryption. This will look for a symmetric-encryption.yml in the config
    # directory and configure Symmetric Encryption appropriately.
    #
    # @example symmetric-encryption.yml
    #
    #   development:
    #     ciphers:
    #       - cipher_name: aes-128-cbc
    #         version:     1
    #         key:         1234567890ABCDEF
    #         iv:          1234567890ABCDEF
    #
    # Honors the `SYMMETRIC_ENCRYPTION_CONFIG` and `SYMMETRIC_ENCRYPTION_ENV` environment
    # variables, and does nothing when a cipher has already been set.
    #
    # Loaded before Active Record initializes since database.yml can have encrypted
    # passwords in it
    config.before_configuration do
      # Check if already configured
      unless ::SymmetricEncryption.cipher?
        parent_method = Module.method_defined?(:module_parent) ? "module_parent" : "parent"
        app_name      = Rails::Application.subclasses.first.send(parent_method).to_s.underscore
        env_var       = ENV.fetch("SYMMETRIC_ENCRYPTION_CONFIG", nil)
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
