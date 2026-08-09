module SymmetricEncryption
  # Generates the accessors that read and write the decrypted value of an encrypted field.
  #
  # Internal use only. Mongoid's `encrypted: true` field option is the only caller, now that
  # `attr_encrypted` has been removed. Active Record uses the `:encrypted` attribute type instead,
  # see `SymmetricEncryption::ActiveRecord::EncryptedAttribute`.
  module Generator
    # Generates `#{decrypted_name}`, `#{decrypted_name}=` and `#{decrypted_name}_changed?` on the
    # supplied model, reading and writing the encrypted value through `#{encrypted_name}`.
    #
    # The accessors go into a per model `EncryptedAttributes` module that is included into the
    # model, so that the model can override them and call `super`.
    #
    # options: [Hash] :type, :random_iv, :compress and :version. See the Mongoid `:encrypted`
    #   field option. Anything else raises, since a misspelled option would otherwise be ignored.
    def self.generate_decrypted_accessors(model, decrypted_name, encrypted_name, options)
      options   = options.dup
      random_iv = options.delete(:random_iv) || false
      compress  = options.delete(:compress) || false
      type      = options.delete(:type) || :string
      version   = options.delete(:version)

      unless options.empty?
        raise(ArgumentError, "SymmetricEncryption Invalid options #{options.inspect} when encrypting '#{decrypted_name}'")
      end
      unless SymmetricEncryption::COERCION_TYPES.include?(type)
        raise(ArgumentError, "Invalid type: #{type.inspect}. Valid types: #{SymmetricEncryption::COERCION_TYPES.inspect}")
      end

      # Do not search ancestors: each model needs its own EncryptedAttributes module.
      if model.const_defined?(:EncryptedAttributes, false)
        mod = model.const_get(:EncryptedAttributes)
      else
        mod = model.const_set(:EncryptedAttributes, Module.new)
        model.send(:include, mod)
      end

      # Generate getter and setter methods.
      # The cop wants a comment against each interpolated def. The worked example at the top of the
      # heredoc covers all three of them at once, which reads better than repeating it.
      # rubocop:disable Style/DocumentDynamicEvalDefinition
      mod.module_eval(<<~ACCESSORS, __FILE__, __LINE__ + 1)
        # For `field :encrypted_ssn, encrypted: true` on a Mongoid model this generates:
        #
        #   def ssn=(value)
        #     v = SymmetricEncryption::Coerce.coerce(value, :string).freeze
        #     return if (@ssn == v) && !v.nil? && !(v == '')
        #     self.encrypted_ssn = @stored_encrypted_ssn =
        #       ::SymmetricEncryption.encrypt(v, random_iv: false, compress: false, type: :string, version: nil).freeze
        #     @ssn = v
        #   end
        #
        #   def ssn
        #     if !defined?(@stored_encrypted_ssn) || (@stored_encrypted_ssn != self.encrypted_ssn)
        #       @ssn = ::SymmetricEncryption.decrypt(self.encrypted_ssn.freeze, type: :string, version: nil).freeze
        #       @stored_encrypted_ssn = self.encrypted_ssn
        #     end
        #     @ssn
        #   end
        #
        #   def ssn_changed?
        #     encrypted_ssn_changed?
        #   end

        # Set the un-encrypted field
        # Also updates the encrypted field with the encrypted value
        # Freeze the decrypted field value so that it is not modified directly
        def #{decrypted_name}=(value)
          v = SymmetricEncryption::Coerce.coerce(value, :#{type}).freeze
          return if (@#{decrypted_name} == v) && !v.nil? && !(v == '')
          self.#{encrypted_name} = @stored_#{encrypted_name} = ::SymmetricEncryption.encrypt(v, random_iv: #{random_iv}, compress: #{compress}, type: :#{type}, version: #{version.inspect}).freeze
          @#{decrypted_name} = v
        end

        # Returns the decrypted value for the encrypted field
        # The decrypted value is cached and is only decrypted if the encrypted value has changed
        # If this method is not called, then the encrypted value is never decrypted
        def #{decrypted_name}
          if !defined?(@stored_#{encrypted_name}) || (@stored_#{encrypted_name} != self.#{encrypted_name})
            @#{decrypted_name} = ::SymmetricEncryption.decrypt(self.#{encrypted_name}.freeze, type: :#{type}, version: #{version.inspect}).freeze
            @stored_#{encrypted_name} = self.#{encrypted_name}
          end
          @#{decrypted_name}
        end

        # Map changes to encrypted value to unencrypted equivalent
        def #{decrypted_name}_changed?
          #{encrypted_name}_changed?
        end
      ACCESSORS
      # rubocop:enable Style/DocumentDynamicEvalDefinition
    end
  end
end
