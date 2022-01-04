module SymmetricEncryption
  module ActiveRecord
    module AttrEncrypted
      def self.included(base)
        base.extend ClassMethods
      end

      module ClassMethods
        # Transparently encrypt and decrypt values stored via ActiveRecord.
        #
        # Parameters:
        # * Symbolic names of each method to create which has a corresponding
        #   method already defined in rails starting with: encrypted_
        # * Followed by an optional hash:
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
        #     :type [Symbol]
        #       The type for this field, #see SymmetricEncryption::COERCION_TYPES
        #       Default: :string
        #
        #     :compress [true|false]
        #       Whether to compress str before encryption
        #       Should only be used for large strings since compression overhead and
        #       the overhead of adding the 'magic' header may exceed any benefits of
        #       compression
        #       Note: Adds a 6 byte header prior to encoding, only if :random_iv is false
        #       Default: false
        def attr_encrypted(*attributes, random_iv: nil, type: :string, compress: false)
          # Ensure ActiveRecord has created all its methods first
          # Ignore failures since the table may not yet actually exist
          begin
            define_attribute_methods
          rescue StandardError
            nil
          end

          random_iv = true if random_iv.nil? && SymmetricEncryption.randomize_iv?

          if random_iv.nil?
            warn("attr_encrypted() no longer allows a default value for option `random_iv`. Add `random_iv: false` if it is required.")
          end

          attributes.each do |attribute|
            SymmetricEncryption::Generator.generate_decrypted_accessors(
              self,
              attribute,
              "encrypted_#{attribute}",
              random_iv: random_iv,
              type:      type,
              compress:  compress
            )
            symmetric_encrypted_attributes[attribute.to_sym] = "encrypted_#{attribute}".to_sym
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
        #   User.symmetric_encrypted_attributes  =>  { email: encrypted_email }
        def symmetric_encrypted_attributes
          @symmetric_encrypted_attributes ||= superclass.respond_to?(:symmetric_encrypted_attributes) ? superclass.symmetric_encrypted_attributes.dup : {}
        end

        # Return the name of all encrypted virtual attributes as an Array of symbols
        # Example: [:email, :password]
        def encrypted_keys
          @encrypted_keys ||= symmetric_encrypted_attributes.keys
        end

        # Return the name of all encrypted columns as an Array of symbols
        # Example: [:encrypted_email, :encrypted_password]
        def encrypted_columns
          @encrypted_columns ||= symmetric_encrypted_attributes.values
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
      end
    end
  end
end
