# encoding: utf-8
module SymmetricEncryption #:nodoc:
  class Railtie < Rails::Railtie #:nodoc:

    # Exposes Symmetric Encryption's configuration to the Rails application configuration.
    #
    # @example Set up configuration in the Rails app.
    #   module MyApplication
    #     class Application < Rails::Application
    #       config.symmetric_encryption.cipher = 'aes-256-cbc'
    #     end
    #   end
    #config.symmetric_encryption = ::SymmetricEncryption::Config

    rake_tasks do
      load "symmetric_encryption/railties/symmetric_encryption.rake"
    end

    # Initialize Symmetry. This will look for a symmetry.yml in the config
    # directory and configure Symmetry appropriately.
    #
    # @example symmetric-encryption.yml
    #
    #   development:
    #     cipher: aes-256-cbc
    #     symmetric_key: 1234567890ABCDEF1234567890ABCDEF
    #     symmetric_iv: 1234567890ABCDEF
    #
    # Loaded before Active Record initializes since database.yml can have encrypted
    # passwords in it
    config.before_configuration do
      config_file = Rails.root.join("config", "symmetric-encryption.yml")
      if config_file.file?
        ::SymmetricEncryption.load!(config_file, Rails.env)
      else
        puts "\nSymmetric Encryption config not found. Create a config file at: config/symmetric-encryption.yml"
        #           puts "to generate one run: rails generate symmetric-encryption:config\n\n"
      end
    end

  end
end
