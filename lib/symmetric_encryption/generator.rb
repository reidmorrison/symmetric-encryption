module SymmetricEncryption
  module Generator
    # Common internal method for generating accessors for decrypted accessors
    # Primarily used by extensions
    def self.generate_decrypted_accessors(model, decrypted_name, encrypted_name, options)
      options   = options.dup
      random_iv = options.delete(:random_iv) || false
      compress  = options.delete(:compress) || false
      type      = options.delete(:type) || :string

      unless options.empty?
        raise(ArgumentError, "SymmetricEncryption Invalid options #{options.inspect} when encrypting '#{decrypted_name}'")
      end
      unless SymmetricEncryption::COERCION_TYPES.include?(type)
        raise(ArgumentError, "Invalid type: #{type.inspect}. Valid types: #{SymmetricEncryption::COERCION_TYPES.inspect}")
      end

      if model.const_defined?(:EncryptedAttributes, _search_ancestors = false)
        mod = model.const_get(:EncryptedAttributes)
      else
        mod = model.const_set(:EncryptedAttributes, Module.new)
        model.send(:include, mod)
      end

      # Generate getter and setter methods
      mod.module_eval(<<~ACCESSORS, __FILE__, __LINE__ + 1)
        # Set the un-encrypted field
        # Also updates the encrypted field with the encrypted value
        # Freeze the decrypted field value so that it is not modified directly
        def #{decrypted_name}=(value)
          v = SymmetricEncryption::Coerce.coerce(value, :#{type}).freeze
          return if (@#{decrypted_name} == v) && !v.nil? && !(v == '')
          self.#{encrypted_name} = @stored_#{encrypted_name} = ::SymmetricEncryption.encrypt(v, random_iv: #{random_iv}, compress: #{compress}, type: :#{type}).freeze
          @#{decrypted_name} = v
        end

        # Returns the decrypted value for the encrypted field
        # The decrypted value is cached and is only decrypted if the encrypted value has changed
        # If this method is not called, then the encrypted value is never decrypted
        def #{decrypted_name}
          if !defined?(@stored_#{encrypted_name}) || (@stored_#{encrypted_name} != self.#{encrypted_name})
            @#{decrypted_name} = ::SymmetricEncryption.decrypt(self.#{encrypted_name}.freeze, type: :#{type}).freeze
            @stored_#{encrypted_name} = self.#{encrypted_name}
          end
          @#{decrypted_name}
        end

        # Map changes to encrypted value to unencrypted equivalent
        def #{decrypted_name}_changed?
          #{encrypted_name}_changed?
        end
      ACCESSORS
    end
  end
end
