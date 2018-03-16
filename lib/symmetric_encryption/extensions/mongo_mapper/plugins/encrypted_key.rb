#
# DEPRECATED !!!
#
module MongoMapper
  module Plugins
    module EncryptedKey
      extend ActiveSupport::Concern

      COERCION_MAP = {
        String     => :string,
        Integer    => :integer,
        Float      => :float,
        BigDecimal => :decimal,
        DateTime   => :datetime,
        Time       => :time,
        Date       => :date,
        Boolean    => :boolean,
        Hash       => :json
      }.freeze

      module ClassMethods
        def encrypted_key(key_name, type, full_options = {})
          full_options = full_options.is_a?(Hash) ? full_options.dup : {}
          options      = full_options.delete(:encrypted) || {}
          # Support overriding the name of the decrypted attribute
          encrypted_key_name = options.delete(:encrypt_as) || "encrypted_#{key_name}"
          options[:type]     = COERCION_MAP[type] unless %i[yaml json].include?(options[:type])

          raise(ArgumentError, "Invalid type: #{type.inspect}. Valid types: #{COERCION_MAP.keys.join(',')}") unless options[:type]

          SymmetricEncryption::Generator.generate_decrypted_accessors(self, key_name, encrypted_key_name, options)

          key(encrypted_key_name, String, full_options)
        end
      end
    end
  end
end

MongoMapper::Document.plugin(MongoMapper::Plugins::EncryptedKey)
MongoMapper::EmbeddedDocument.plugin(MongoMapper::Plugins::EncryptedKey)
