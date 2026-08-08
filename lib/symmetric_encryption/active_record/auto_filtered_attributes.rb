module SymmetricEncryption
  module ActiveRecord
    # Adds every attribute declared with the `:encrypted` type to the model's `filter_attributes`,
    # so that the decrypted value is never written out by `inspect`, `attribute_for_inspect`, or
    # anything else that renders a record into the log:
    #
    #   class Person < ActiveRecord::Base
    #     attribute :ssn, :encrypted
    #   end
    #
    #   Rails.logger.info(person)
    #   # Before: #<Person id: 1, ssn: "top_secret">
    #   # After:  #<Person id: 1, ssn: [FILTERED]>
    #
    # This mirrors what Active Record's own `encrypts` does through
    # `ActiveRecord::Encryption::AutoFilteredParameters`, including adding `"person.ssn"` to the
    # Rails application's `config.filter_parameters` so that the value is also filtered out of the
    # request parameters in the logs.
    #
    # Filtering applies to `inspect` and to logging only, which is as far as Active Record itself
    # goes. It does _not_ remove the attribute from `as_json`, since an encrypted attribute that is
    # deliberately rendered into an API response has to keep working. Include
    # SymmetricEncryption::ActiveRecord::ExcludeFromJson in the model for that.
    #
    # Turn it off before the models are loaded, when the filtering is not wanted:
    #   config.symmetric_encryption.filter_encrypted_attributes = false
    module AutoFilteredAttributes
      # Active Record has changed the signature of `attribute` several times, so take whatever it
      # is given and hand it straight back to Active Record.
      def attribute(name, *args, **options, &)
        filter_encrypted_attribute(name) if SymmetricEncryption.filter_encrypted_attributes? && encrypted_type?(args.first)
        super
      end

      private

      def encrypted_type?(cast_type)
        (cast_type == :encrypted) || cast_type.is_a?(EncryptedAttribute)
      end

      def filter_encrypted_attribute(attribute_name)
        attribute_name = attribute_name.to_sym
        self.filter_attributes += [attribute_name] unless filter_attributes.include?(attribute_name)
        add_to_filter_parameters(attribute_name)
      end

      # Filters the attribute out of the request parameters in the Rails logs, in the same
      # `model.attribute` format that Active Record's own encryption uses.
      def add_to_filter_parameters(attribute_name)
        return unless defined?(::Rails) && ::Rails.respond_to?(:application)

        config = ::Rails.application&.config
        # An anonymous model has no `model_name`, so there is no parameter name to filter on.
        return if config.nil? || name.nil?

        filter = "#{model_name.element}.#{attribute_name}"
        config.filter_parameters << filter unless config.filter_parameters.include?(filter)
      end
    end
  end
end
