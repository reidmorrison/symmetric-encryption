# encoding: utf-8
module Symmetric #:nodoc:
  class Railtie < Rails::Railtie #:nodoc:

    # Exposes Symmetric Encryption's configuration to the Rails application configuration.
    #
    # @example Set up configuration in the Rails app.
    #   module MyApplication
    #     class Application < Rails::Application
    #       config.symmetric_encryption.cipher = 'aes-256-cbc'
    #     end
    #   end
    #config.symmetric_encryption = ::Symmetric::Config

    rake_tasks do
      load "symmetric/railties/symmetric_encryption.rake"
    end

    # Initialize Symmetry. This will look for a symmetry.yml in the config
    # directory and configure Symmetry appropriately.
    #
    # @example symmetry.yml
    #
    #   development:
    #     cipher: aes-256-cbc
    #     symmetric_key: 1234567890ABCDEF1234567890ABCDEF
    #     symmetric_iv: 1234567890ABCDEF
    #
    initializer "load symmetry encryption keys" do
      config.before_initialize do
        config_file = Rails.root.join("config", "symmetric-encryption.yml")
        if config_file.file?
          ::Symmetric::Encryption.load!(config_file, Rails.env)
        else
          puts "\nSymmetric Encryption config not found. Create a config file at: config/symmetric-encryption.yml"
          #            puts "to generate one run: rails generate symmetric-encryption:config\n\n"
        end
      end
    end

  end
end
