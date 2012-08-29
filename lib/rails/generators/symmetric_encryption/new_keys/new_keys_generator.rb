module SymmetricEncryption
  module Generators
    class NewKeysGenerator < Rails::Generators::Base
      desc "Generate new Symmetric key and initialization vector based on values in config/symmetric-encryption.yml"
      
      argument :environment, :type => :string, :optional => false

      def create_config_file
        SymmetricEncryption.generate_symmetric_key_files(File.join('config', "symmetric-encryption.yml"), environment)
      end

    end
  end
end
