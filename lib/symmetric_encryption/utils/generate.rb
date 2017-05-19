module SymmetricEncryption
  module Utils
    class Generate
      # Generate a new config file
      # Returns the name of the new configuration file
      def config(heroku: false,
                 key_path: '/etc/symmetric-encryption',
                 app_name: 'symmetric-encryption',
                 filename: 'config/symmetric-encryption.yml')

        # key_path and app_name are used in the template
        template      = heroku ? 'heroku_config/templates' : 'config/templates'
        template_path = File.expand_path("../../rails/generators/symmetric_encryption/#{template}", __FILE__)
        data          = File.read(template_path)

        File.open(filename, 'w') do |f|
          f << ERB.new(data, nil, '-').result(binding)
        end

        filename
      end

    end
  end
end
