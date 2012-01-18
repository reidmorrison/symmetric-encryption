module ActiveRecord #:nodoc:
  class Base

    class << self # Class methods
      # Much lighter weight encryption for Rails attributes matching the
      # attr_encrypted interface using Symmetry::Encryption
      #
      # The regular attr_encrypted gem uses Encryptor that adds encryption to
      # every Ruby object which is a complete overkill for this simple use-case
      #
      # Params:
      # * symbolic names of each method to create which has a corresponding
      #   method already defined in rails starting with: encrypted_
      # * Followed by an option hash:
      #      :marshal => Whether this element should be converted to YAML before encryption
      #                  true or false
      #                  Default: false
      #
      def attr_encrypted(*params)
        # Ensure ActiveRecord has created all its methods first
        # Ignore failures since the table may not yet actually exist
        define_attribute_methods rescue nil

        options = params.last.is_a?(Hash) ? params.pop : {}

        params.each do |attribute|
          # Generate unencrypted attribute with getter and setter
          class_eval <<-UNENCRYPTED_GETTER
            def #{attribute}
              @#{attribute} = ::Symmetric::Encryption.decrypt(self.encrypted_#{attribute}) if @#{attribute}.nil? && !self.encrypted_#{attribute}.nil?
              @#{attribute}
            end
          UNENCRYPTED_GETTER

          # Encrypt value immediately when unencrypted value is set
          # Unencrypted value is also kept for performance reasons
          class_eval <<-UNENCRYPTED_SETTER
            def #{attribute}=(value)
              self.encrypted_#{attribute} = ::Symmetric::Encryption.encrypt(value#{".to_yaml" if options[:marshal]})
              @#{attribute} = value
            end
          UNENCRYPTED_SETTER

          encrypted_attributes[attribute.to_sym] = "encrypted_#{attribute}".to_sym
        end
      end

      # Contains a hash of encrypted attributes with virtual attribute names as keys and real attribute
      # names as values
      #
      # Example
      #
      #   class User < ActiveRecord::Base
      #     attr_encrypted :email
      #   end
      #
      #   User.encrypted_attributes # { :email => :encrypted_email }
      def encrypted_attributes
        @encrypted_attributes ||= superclass.respond_to?(:encrypted_attributes) ? superclass.encrypted_attributes.dup : {}
      end

      # Return the name of all encrypted virtual attributes as an Array of symbols
      # Example: [:email, :password]
      def encrypted_keys
        @encrypted_keys ||= encrypted_attributes.keys
      end

      # Return the name of all encrypted columns as an Array of symbols
      # Example: [:encrypted_email, :encrypted_password]
      def encrypted_columns
        @encrypted_columns ||= encrypted_attributes.values
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
      def encrypted_attribute?(attribute)
        encrypted_keys.include?(attribute)
      end

      # Returns whether the attribute is the database column to hold the
      # encrypted data for a matching encrypted attribute
      #
      # Example
      #
      #   class User < ActiveRecord::Base
      #     attr_accessor :name
      #     attr_encrypted :email
      #   end
      #
      #   User.encrypted_column?(:encrypted_name) # false
      #   User.encrypted_column?(:encrypted_email) # true
      def encrypted_column?(attribute)
        encrypted_columns.include?(attribute)
      end

      protected

      # Allows you to use dynamic methods like <tt>find_by_email</tt> or <tt>scoped_by_email</tt> for
      # encrypted attributes
      #
      # This is useful for encrypting fields like email addresses. Your user's email addresses
      # are encrypted in the database, but you can still look up a user by email for logging in
      #
      # Example
      #
      #   class User < ActiveRecord::Base
      #     attr_encrypted :email
      #   end
      #
      #   User.find_by_email_and_password('test@example.com', 'testing')
      #   # results in a call to
      #   User.find_by_encrypted_email_and_password('the_encrypted_version_of_test@example.com', 'testing')
      def method_missing_with_attr_encrypted(method, *args, &block)
        if match = /^(find|scoped)_(all_by|by)_([_a-zA-Z]\w*)$/.match(method.to_s)
          attribute_names = match.captures.last.split('_and_')
          attribute_names.each_with_index do |attribute, index|
            encrypted_name = "encrypted_#{attribute}"
            if instance_methods.include? encrypted_name #.to_sym in 1.9
              args[index] = ::Symmetric::Encryption.encrypt(args[index])
              attribute_names[index] = encrypted_name
            end
          end
          method = "#{match.captures[0]}_#{match.captures[1]}_#{attribute_names.join('_and_')}".to_sym
        end
        method_missing_without_attr_encrypted(method, *args, &block)
      end

      alias_method_chain :method_missing, :attr_encrypted
      #Equivalent to:
      #  alias_method :method_missing_without_attr_encrypted, :attr_encrypted # new, old
      #  alias_method :attr_encrypted, :method_missing_with_attr_encrypted

    end
  end
end
