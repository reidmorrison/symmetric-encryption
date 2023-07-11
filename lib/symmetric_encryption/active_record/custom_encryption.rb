module CustomEncryption
  def self.included(base)
    base.extend ClassMethods
  end

  module ClassMethods
    # Contains a hash of encrypted attributes with virtual attribute names as keys and real attribute
    # names as values
    def custom_encrypted_attributes
      @custom_encrypted_attributes ||= superclass.respond_to?(:custom_encrypted_attributes) ? superclass.custom_encrypted_attributes.dup : {}
    end

    # Return the name of all encrypted virtual attributes as an Array of symbols
    # Example: [:email, :password]
    def custom_encrypted_keys
      @custom_encrypted_keys ||= custom_encrypted_attributes.keys
    end

    # Return the name of all encrypted columns as an Array of symbols
    # Example: [:encrypted_email, :encrypted_password]
    def custom_encrypted_columns
      @custom_encrypted_columns ||= custom_encrypted_attributes.values
    end

    # Returns whether an attribute has been configured to be encrypted
    #
    # Example
    #
    #   class User < ActiveRecord::Base
    #     attr_accessor :name
    #     attr_encrypted :email
    #   end
    #
    #   User.encrypted_attribute?(:name) # false
    #   User.encrypted_attribute?(:email) # true
    def custom_encrypted_attribute?(attribute)
      custom_encrypted_keys.include?(attribute)
    end

    # Returns whether the attribute is the database column to hold the
    # encrypted data for a matching encrypted attribute
    def custom_encrypted_column?(attribute)
      custom_encrypted_columns.include?(attribute)
    end
  end
end
