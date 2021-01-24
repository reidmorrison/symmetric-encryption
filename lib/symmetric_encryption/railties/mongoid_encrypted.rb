require "mongoid"
# Add :encrypted option for Mongoid models
#
# Example:
#
#  require 'mongoid'
#  require 'symmetric-encryption'
#
#  # Initialize Mongoid in a standalone environment. In a Rails app this is not required
#  Mongoid.logger = Logger.new($stdout)
#  Mongoid.load!('config/mongoid.yml')
#
#  # Initialize SymmetricEncryption in a standalone environment. In a Rails app this is not required
#  SymmetricEncryption::Config.load!('config/symmetric-encryption.yml', 'test')
#
#  class Person
#    include Mongoid::Document
#
#    field :name,                             type: String
#    field :encrypted_social_security_number, type: String, encrypted: true
#    field :date_of_birth,                    type: Date
#    field :encrypted_life_history,           type: String, encrypted: {compress: true, random_iv: true}
#
#    # Encrypted fields are _always_ stored in Mongo as a String
#    # To get the result back as an Integer, Symmetric Encryption can do the
#    # necessary conversions by specifying the internal type as an option
#    # to :encrypted
#    # #see SymmetricEncryption::COERCION_TYPES for full list of types
#    field :encrypted_age,                    type: String, encrypted: {type: :integer, random_iv: true}
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
# in it's unencrypted form. For example
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
# @example Define a field.
#   field :social_security_number, type: String, encrypted: {compress: false, random_iv: false}
#   field :sensitive_text, type: String, encrypted: {compress: true, random_iv: true}
#
# @param [ Symbol ] name The name of the field.
# @param [ Hash ] options The options to pass to the field.
#
# @option options [ Boolean | Hash ] :encrypted  If the field contains encrypted data.
#   When :encrypted is a Hash it consists of:
#     @option options [ Symbol ]  :type The type for this field, #see SymmetricEncryption::COERCION_TYPES
#     @option options [ Boolean ] :random_iv  Whether the encrypted value should use a random IV every time the field is encrypted.
#     @option options [ Boolean ] :compress   Whether to compress this encrypted field
#     @option options [ Symbol ]  :decrypt_as Name of the getters and setters to generate to access the decrypted value of this field.
#
# Some of the other regular Mongoid options:
#
# @option options [ Class ]   :type The type of the field.
# @option options [ String ]  :label The label for the field.
# @option options [ Object, Proc ] :default The fields default
#
# @return [ Field ] The generated field
Mongoid::Fields.option :encrypted do |model, field, options|
  if options != false
    options              = options.is_a?(Hash) ? options.dup : {}
    encrypted_field_name = field.name

    # Support overriding the name of the decrypted attribute
    decrypted_field_name = options.delete(:decrypt_as)
    if decrypted_field_name.nil? && encrypted_field_name.to_s.start_with?("encrypted_")
      decrypted_field_name = encrypted_field_name.to_s["encrypted_".length..-1]
    end

    if decrypted_field_name.nil?
      raise(ArgumentError,
            "SymmetricEncryption for Mongoid. Encryption enabled for field #{encrypted_field_name}. It must either start with 'encrypted_' or the option :decrypt_as must be supplied")
    end

    SymmetricEncryption::Generator.generate_decrypted_accessors(model, decrypted_field_name, encrypted_field_name, options)
  end
end
