module ActiveRecord #:nodoc:
  class Base

    class << self # Class methods
      # Drop in replacement for attr_encrypted gem, except that it uses
      # SymmetricEncryption for managing the encryption key
      #
      # Parameters:
      # * Symbolic names of each method to create which has a corresponding
      #   method already defined in rails starting with: encrypted_
      # * Followed by an optional hash:
      #     :marshal [true|false]
      #       Whether this element should be converted to YAML before encryption
      #       Default: false
      #
      #     :random_iv [true|false]
      #       Whether the encrypted value should use a random IV every time the
      #       field is encrypted.
      #       It is recommended to set this to true where feasible. If the encrypted
      #       value could be used as part of a SQL where clause, or as part
      #       of any lookup, then it must be false.
      #       Setting random_iv to true will result in a different encrypted output for
      #       the same input string.
      #       Note: Only set to true if the field will never be used as part of
      #         the where clause in an SQL query.
      #       Note: When random_iv is true it will add a 8 byte header, plus the bytes
      #         to store the random IV in every returned encrypted string, prior to the
      #         encoding if any.
      #       Default: false
      #       Highly Recommended where feasible: true
      #
      #     :compress [true|false]
      #       Whether to compress str before encryption
      #       Should only be used for large strings since compression overhead and
      #       the overhead of adding the 'magic' header may exceed any benefits of
      #       compression
      #       Note: Adds a 6 byte header prior to encoding, only if :random_iv is false
      #       Default: false
      def attr_encrypted(*params)
        # Ensure ActiveRecord has created all its methods first
        # Ignore failures since the table may not yet actually exist
        define_attribute_methods rescue nil

        options = params.last.is_a?(Hash) ? params.pop : {}
        random_iv = options.fetch(:random_iv, false)
        compress  = options.fetch(:compress, false)
        marshal   = options.fetch(:marshal, false)

        params.each do |attribute|
          # Generate unencrypted attribute with getter and setter
          class_eval(<<-UNENCRYPTED, __FILE__, __LINE__ + 1)
            # Returns the decrypted value for the encrypted attribute
            # The decrypted value is cached and is only decrypted if the encrypted value has changed
            # If this method is not called, then the encrypted value is never decrypted
            def #{attribute}
              if @stored_encrypted_#{attribute} != self.encrypted_#{attribute}
                @#{attribute} = ::SymmetricEncryption.decrypt(self.encrypted_#{attribute}).freeze
                @stored_encrypted_#{attribute} = self.encrypted_#{attribute}
              end
              @#{attribute}
            end

            # Set the un-encrypted attribute
            # Also updates the encrypted field with the encrypted value
            def #{attribute}=(value)
              self.encrypted_#{attribute} = @stored_encrypted_#{attribute} = ::SymmetricEncryption.encrypt(value#{".to_yaml" if marshal},#{random_iv},#{compress})
              @#{attribute} = value.freeze
            end
          UNENCRYPTED

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
            if method_defined? encrypted_name.to_sym
              args[index] = ::SymmetricEncryption.encrypt(args[index])
              attribute_names[index] = encrypted_name
            end
          end
          method = "#{match.captures[0]}_#{match.captures[1]}_#{attribute_names.join('_and_')}".to_sym
        end
        method_missing_without_attr_encrypted(method, *args, &block)
      end

      alias_method_chain :method_missing, :attr_encrypted

    end
  end
end
