module SymmetricEncryption
  module Generators
    class HerokuConfigGenerator < Rails::Generators::Base
      desc "Creates a SymmetricEncryption configuration file at config/symmetric-encryption.yml for use in heroku"

      def self.source_root
        @_symmetric_encryption_source_root ||= File.expand_path("../templates", __FILE__)
      end

      def app_name
        Rails::Application.subclasses.first.parent.to_s.underscore
      end

      def create_config_file
        template 'symmetric-encryption.yml', File.join('config', "symmetric-encryption.yml")
      end

    end
  end
end
