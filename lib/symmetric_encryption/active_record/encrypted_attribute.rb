module SymmetricEncryption
  module ActiveRecord
    class EncryptedAttribute < ::ActiveModel::Type::String
      # Types whose casting rules are handed straight to Active Record, so that an encrypted
      # attribute casts assigned values exactly like the equivalent unencrypted one.
      # @formatter:off
      RAILS_CAST_TYPES = {
        integer: ::ActiveModel::Type::Integer,
        float:   ::ActiveModel::Type::Float,
        decimal: ::ActiveModel::Type::Decimal,
        boolean: ::ActiveModel::Type::Boolean
      }.freeze
      # @formatter:on

      def initialize(random_iv: true, compress: false, type: :string)
        unless SymmetricEncryption::COERCION_TYPES.include?(type)
          raise(ArgumentError, "Invalid type: #{type.inspect}. Valid types: #{SymmetricEncryption::COERCION_TYPES.inspect}")
        end

        super()
        @random_iv      = random_iv
        @compress       = compress
        @encrypted_type = type
        @rails_type     = RAILS_CAST_TYPES[type]&.new
      end

      def deserialize(value)
        return if value.nil?

        SymmetricEncryption.decrypt(value, type: encrypted_type)
      end

      def serialize(value)
        value = cast(value)
        return if value.nil?

        SymmetricEncryption.encrypt(
          value,
          type:      encrypted_type,
          compress:  compress,
          random_iv: random_iv
        )
      end

      # A random iv makes the encrypted value differ every time it is written, so compare the
      # decrypted values rather than the encrypted ones.
      def changed_in_place?(raw_old_value, new_value)
        # Nothing was read from the database, so the value was assigned, not changed in place.
        # Active Record skips `*_before_type_cast` while an attribute is changed in place, which
        # is what `validates :age, numericality: true` needs to report the value the user supplied.
        return false if raw_old_value.nil?

        deserialize(raw_old_value) != new_value
      end

      private

      # Cast the assigned value to the declared type, so that an attribute returns the same type
      # before and after it has been saved and read back.
      #
      # Follows Active Record: casting never raises, a blank string becomes nil for every type
      # other than :string, and a value that cannot be cast is turned into the same value that
      # Active Record would use for an unencrypted attribute of that type.
      def cast_value(value)
        return rails_type.cast(value) if rails_type

        case encrypted_type
        when :string
          # Not ActiveModel::Type::String#cast_value, which casts true to "t". #serialize writes
          # the value as `to_s`, so cast it the same way.
          value.to_s
        when :json, :yaml
          # Left as assigned, as Active Record's own :json type also does.
          value
        else
          cast_time_value(value)
        end
      end

      # Dates and times are cast by the coercible gem rather than by Active Record, because
      # ActiveModel::Type::Time discards the date portion of the value it is given, and
      # ActiveModel::Type::DateTime returns a Time for a string, not the DateTime that reading
      # the attribute back returns.
      def cast_time_value(value)
        return if value.is_a?(::String) && value.blank?

        value = Coerce.coerce(value, encrypted_type)
        # Coercible returns some values unchanged instead of raising. Follow Active Record and
        # return nil for anything it could not turn into the declared type.
        value.is_a?(Coerce::TYPE_MAP[encrypted_type]) ? value : nil
      rescue Coercible::UnsupportedCoercion
        nil
      end

      attr_reader :random_iv, :compress, :encrypted_type, :rails_type
    end
  end
end
