module SymmetricEncryption
  module ActiveRecord
    # Excludes every attribute declared with the `:encrypted` type from the JSON representation of
    # the model, so that a decrypted value is never rendered by `render json:`:
    #
    #   class Person < ActiveRecord::Base
    #     include SymmetricEncryption::ActiveRecord::ExcludeFromJson
    #
    #     attribute :ssn, :encrypted
    #   end
    #
    #   Person.create(name: "Jack", ssn: "top_secret").as_json
    #   # Before: {"id" => 1, "name" => "Jack", "ssn" => "top_secret"}
    #   # After:  {"id" => 1, "name" => "Jack"}
    #
    # Opt-in, because an encrypted attribute is otherwise indistinguishable from an unencrypted one,
    # and because Active Record's own `encrypts` also renders decrypted values into JSON. Removing
    # them by default would silently change the response of an API that deliberately returns one.
    #
    # `:only` cannot bring an encrypted attribute back, since the point of including this module is
    # that the value cannot leak into a response by accident. Rendering one is a deliberate act, so
    # it takes asking for it by name:
    #
    #   person.as_json(methods: :ssn)
    #   # => {"id" => 1, "name" => "Jack", "ssn" => "top_secret"}
    #
    # Encrypted attributes are still visible to `attributes`, `to_yaml`, and anything else that does
    # not go through `serializable_hash`.
    module ExcludeFromJson
      # `as_json`, `to_json` and `serializable_hash` all end up here.
      def serializable_hash(options = nil)
        excluded = encrypted_attribute_names
        return super if excluded.empty?

        options          = options.nil? ? {} : options.dup
        options[:except] = Array(options[:except]) + excluded

        # Passes the `options` above, since `super` without arguments picks up the current values.
        hash = super
        # Active Record ignores `:except` when the caller supplied `:only`, so remove them again.
        remove_encrypted_attributes(hash, excluded, options) if options[:only]
        hash
      end

      private

      def encrypted_attribute_names
        self.class.attribute_types.select { |_name, type| type.is_a?(EncryptedAttribute) }.keys
      end

      # Leaves anything named in `:methods` in place, since that was asked for by name.
      def remove_encrypted_attributes(hash, excluded, options)
        methods = Array(options[:methods]).map(&:to_s)
        excluded.each { |attribute_name| hash.delete(attribute_name) unless methods.include?(attribute_name) }
      end
    end
  end
end
