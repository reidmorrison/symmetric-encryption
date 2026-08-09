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
#  SymmetricEncryption::Config.load!(file_name: 'config/symmetric-encryption.yml', env: 'test')
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
# The above document results in the following document in the Mongo collection 'people':
# {
#   'name' : 'Joe',
#   'date_of_birth' : ISODate('2004-01-01'),
#   'encrypted_social_security_number' : '...',
#   'encrypted_life_history' : '...',
#   'encrypted_age' : '...'
# }
#
# Every encrypted field is stored as a String, whatever its :type option says. The :type is what
# the generated getter coerces the decrypted value back into, so `person.age` returns an Integer.
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
# Note: The Mongoid field itself must be declared `type: String`, since the encrypted value is
#   always a String. Use the :type option above to choose what the decrypted value is coerced to.
#
# Note: Finders must use the encrypted field name, since only the encrypted field is stored.
#   Invalid Example, does not work:
#     person = Person.where(social_security_number: '123456789').first
#
#   Valid Example:
#     person = Person.where(encrypted_social_security_number: SymmetricEncryption.encrypt('123456789')).first
#
#   Note: A field encrypted with `random_iv: true` encrypts to a different value every time, so it
#     cannot be looked up this way at all.
#
# Registers the `:encrypted` option on Mongoid fields. For each field declared with it, a getter,
# a setter and a `_changed?` method for the decrypted value are added to the Document.
#
# @example Declare an encrypted field.
#   field :encrypted_social_security_number, type: String, encrypted: {compress: false, random_iv: false}
#   field :encrypted_sensitive_text,         type: String, encrypted: {compress: true, random_iv: true}
#
# @option options [ Boolean | Hash ] :encrypted  Whether the field contains encrypted data.
#   `true` accepts the defaults below. When :encrypted is a Hash it consists of:
#     @option options [ Symbol ]  :type The type to coerce the decrypted value to,
#       #see SymmetricEncryption::COERCION_TYPES. Default: :string
#     @option options [ Boolean ] :random_iv  Whether the encrypted value should use a random IV
#       every time the field is encrypted. Default: false
#     @option options [ Boolean ] :compress   Whether to compress this encrypted field.
#       Default: false
#     @option options [ Integer ] :version    Encrypt with the cipher that has this version,
#       instead of the primary cipher. Default: the primary cipher.
#     @option options [ Symbol ]  :decrypt_as Name of the getters and setters to generate to access
#       the decrypted value of this field.
#       Default: the field name with the leading `encrypted_` removed, which is then mandatory.
Mongoid::Fields.option :encrypted do |model, field, options|
  if options != false
    options              = options.is_a?(Hash) ? options.dup : {}
    encrypted_field_name = field.name

    # Support overriding the name of the decrypted attribute
    decrypted_field_name = options.delete(:decrypt_as)
    if decrypted_field_name.nil? && encrypted_field_name.to_s.start_with?("encrypted_")
      decrypted_field_name = encrypted_field_name.to_s[("encrypted_".length)..]
    end

    if decrypted_field_name.nil?
      raise(ArgumentError,
            "SymmetricEncryption for Mongoid. Encryption enabled for field #{encrypted_field_name}. " \
            "It must either start with 'encrypted_' or the option :decrypt_as must be supplied")
    end

    SymmetricEncryption::Generator.generate_decrypted_accessors(model, decrypted_field_name, encrypted_field_name, options)
  end
end
