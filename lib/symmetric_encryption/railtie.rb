# encoding: utf-8
module SymmetricEncryption #:nodoc:
  class Railtie < Rails::Railtie #:nodoc:

    # Exposes Symmetric Encryption's configuration to the Rails application configuration.
    #
    # @example Set up configuration in the Rails app.
    #   module MyApplication
    #     class Application < Rails::Application
    #       config.symmetric_encryption.cipher = SymmetricEncryption::Cipher.new(
    #         :key    => '1234567890ABCDEF1234567890ABCDEF',
    #         :iv     => '1234567890ABCDEF',
    #         :cipher_name => 'aes-128-cbc'
    #       )
    #     end
    #   end
    config.symmetric_encryption = ::SymmetricEncryption

    rake_tasks do
      load "symmetric_encryption/railties/symmetric_encryption.rake"
    end

    # Initialize Symmetry. This will look for a symmetry.yml in the config
    # directory and configure Symmetry appropriately.
    #
    # @example symmetric-encryption.yml
    #
    #   development:
    #     cipher_name: aes-256-cbc
    #     key:         1234567890ABCDEF1234567890ABCDEF
    #     iv:          1234567890ABCDEF
    #
    # Loaded before Active Record initializes since database.yml can have encrypted
    # passwords in it
    config.before_configuration do
      config_file = Rails.root.join("config", "symmetric-encryption.yml")
      if config_file.file?
        ::SymmetricEncryption.load!(config_file, Rails.env)
      else
        puts "\nSymmetric Encryption config not found."
        puts "To generate one for the first time: rails generate symmetric_encryption:config\n\n"
      end
    end

  end
end
