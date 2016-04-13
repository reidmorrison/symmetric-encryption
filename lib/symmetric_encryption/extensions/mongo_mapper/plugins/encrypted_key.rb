# Support Encryption and decryption of fields in MongoMapper
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
      }

      module ClassMethods
        # MongoMapper::Document.encrypted_key
        #
        # Support automatic encryption and decryption of fields in MongoMapper
        #
        # Example:
        #
        #  class Person
        #    include MongoMapper::Document
        #
        #    key           :name,                   String
        #    encrypted_key :social_security_number, String
        #    key           :date_of_birth,          Date
        #    encrypted_key :life_history,           String, encrypted: { compress: true, random_iv: true }
        #
        #    # Encrypted fields are _always_ stored in Mongo as a String
        #    # By specifying a type other than String, Symmetric Encryption will
        #    # perform the necessary conversions
        #    #
        #    # The following types are supported:
        #    #   String
        #    #   Integer
        #    #   Float
        #    #   BigDecimal
        #    #   DateTime
        #    #   Time
        #    #   Date
        #    #   Hash - (Stored as encrypted JSON in MongoDB)
        #    encrypted_key :age,                    Integer, encrypted: { random_iv: true }
        #  end
        #
        # The above document results in the following document in the Mongo collection 'persons':
        # {
        #   'name' : 'Joe',
        #   'encrypted_social_security_number' : '...',
        #   'age'  : 21
        #   'encrypted_life_history' : '...',
        # }
        #
        # Symmetric Encryption creates the getters and setters to be able to work with the field
        # in it's decrypted form. For example
        #
        # Example:
        #   person = Person.where(encrypted_social_security_number: '...').first
        #
        #   puts "Decrypted Social Security Number is: #{person.social_security_number}"
        #
        #   # Or is the same as
        #   puts "Decrypted Social Security Number is: #{SymmetricEncryption.decrypt(person.encrypted_social_security_number)}"
        #
        #   # Sets the encrypted_social_security_number to encrypted version
        #   person.social_security_number = '123456789'
        #
        #   # Or, is equivalent to:
        #   person.encrypted_social_security_number = SymmetricEncryption.encrypt('123456789')
        #
        # Note: Only 'String' types are currently supported for encryption
        #
        # Note: Unlike attr_encrypted finders must use the encrypted field name
        #   Invalid Example, does not work:
        #     person = Person.where(social_security_number: '123456789').first
        #
        #   Valid Example:
        #     person = Person.where(encrypted_social_security_number: SymmetricEncryption.encrypt('123456789')).first
        #
        # Defines all the fields that are accessible on the Document
        # For each field that is defined, a getter and setter will be
        # added as an instance method to the Document.
        #
        # @example Define an encrypted key
        #   encrypted_key :social_security_number, String, encrypted: {compress: false, random_iv: false}
        #   encrypted_key :sensitive_text,         String, encrypted: {compress: true, random_iv: true}
        #
        # @param [ Symbol ] name The name of the key.
        # @param [ Object ] type The type of the key.
        # @param [ Hash ] options The options to pass to the field, including any MongoMapper specific options
        #
        # @option options [ Hash ] :encrypted consists of:
        #     @option options [ Boolean ] :random_iv  Whether the encrypted value should use a random IV every time the field is encrypted.
        #     @option options [ Boolean ] :compress   Whether to compress this encrypted field
        #     @option options [ Symbol ]  :encrypt_as Name of the encypted field in Mongo
        #
        #     Some of the other regular MongoMapper options:
        #       :default, :alias, :field_name, :accessors, :abbr
        #
        # Note:
        #   Use MongoMapper's built-in support for :field_name to specify a different
        #   field name in MongoDB for the encrypted field from what is used via the model
        #
        def encrypted_key(key_name, type, full_options={})
          full_options       = full_options.is_a?(Hash) ? full_options.dup : {}
          options            = full_options.delete(:encrypted) || {}
          # Support overriding the name of the decrypted attribute
          encrypted_key_name = options.delete(:encrypt_as) || "encrypted_#{key_name}"
          options[:type]     = COERCION_MAP[type] unless [:yaml, :json].include?(options[:type])

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
