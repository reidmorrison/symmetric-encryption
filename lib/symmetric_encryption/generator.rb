module SymmetricEncryption
  module Generator
    # Common internal method for generating accessors for decrypted accessors
    # Primarily used by extensions
    def self.generate_decrypted_accessors(model, decrypted_name, encrypted_name, options)

      random_iv      = options.delete(:random_iv) || false
      compress       = options.delete(:compress) || false
      type           = options.delete(:type) || :string

      # For backward compatibility
      if options.delete(:marshal) == true
        warn("The :marshal option has been deprecated in favor of :type. For example: attr_encrypted name, type: :yaml")
        raise "Marshal is depreacted and cannot be used in conjunction with :type, just use :type. For #{params.inspect}" if type != :string
        type = :yaml
      end

      options.each {|option| warn "Ignoring unknown option #{option.inspect} supplied when encrypting #{decrypted_name}"}

      raise "Invalid type: #{type.inspect}. Valid types: #{SymmetricEncryption::COERCION_TYPES.inspect}" unless SymmetricEncryption::COERCION_TYPES.include?(type)

      if model.const_defined?(:EncryptedAttributes, _search_ancestors = false)
        mod = model.const_get(:EncryptedAttributes)
      else
        mod = model.const_set(:EncryptedAttributes, Module.new)
        model.send(:include, mod)
      end

      # Generate getter and setter methods
      mod.module_eval(<<-EOS, __FILE__, __LINE__ + 1)
      # Set the un-encrypted field
      # Also updates the encrypted field with the encrypted value
      # Freeze the decrypted field value so that it is not modified directly
      def #{decrypted_name}=(value)
        v = SymmetricEncryption::coerce(value, :#{type})
        self.#{encrypted_name} = @stored_#{encrypted_name} = ::SymmetricEncryption.encrypt(v,#{random_iv},#{compress},:#{type})
        @#{decrypted_name} = v.freeze
      end

      # Returns the decrypted value for the encrypted field
      # The decrypted value is cached and is only decrypted if the encrypted value has changed
      # If this method is not called, then the encrypted value is never decrypted
      def #{decrypted_name}
        if @stored_#{encrypted_name} != self.#{encrypted_name}
          @#{decrypted_name} = ::SymmetricEncryption.decrypt(self.#{encrypted_name},version=nil,:#{type}).freeze
          @stored_#{encrypted_name} = self.#{encrypted_name}
        end
        @#{decrypted_name}
      end

      EOS
    end
  end
end
