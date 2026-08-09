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

      # Types that accept a multiparameter assignment: the Hash keyed by parameter position that
      # Active Record builds from the `name(1i)`, `name(2i)`, ... fields a `date_select` submits.
      # Active Record's own type turns it into a time, so that the same defaults for the missing
      # parameters and the same time zone apply as for an unencrypted attribute.
      MULTIPARAMETER_TYPES = {
        datetime: ::ActiveModel::Type::DateTime,
        time:     ::ActiveModel::Type::Time,
        date:     ::ActiveModel::Type::Date
      }.freeze
      # @formatter:on

      # The `:encrypted` attribute type:
      #
      #   attribute :ssn, :encrypted
      #   attribute :age, :encrypted, type: :integer
      #
      # random_iv [true|false]
      #   Whether to encrypt with a new random iv every time the attribute is written, so that the
      #   same value does not encrypt to the same cipher text twice.
      #   Set this to false when the attribute is looked up by its encrypted value, which needs the
      #   same input to encrypt to the same output.
      #   Default: true
      #
      # compress [true|false]
      #   Whether to compress the value before encrypting it. Only worth it for large values, since
      #   compression has an overhead of its own.
      #   Default: false
      #
      # type [Symbol]
      #   What the attribute holds, one of SymmetricEncryption::COERCION_TYPES. Assigned values are
      #   cast to it exactly as Active Record casts an unencrypted attribute of that type, so
      #   `attribute :age, :encrypted, type: :integer` behaves like `attribute :age, :integer`.
      #   Default: :string
      #
      # version [Integer]
      #   Encrypt this attribute with the cipher that has this version, instead of the primary
      #   cipher, so that it can be encrypted with a key of its own:
      #
      #     attribute :api_key, :encrypted, version: 3
      #
      #   Decryption reads the version out of each value's header, so changing this leaves values
      #   that were already written readable.
      #   Default: the primary cipher.
      def initialize(random_iv: true, compress: false, type: :string, version: nil)
        unless SymmetricEncryption::COERCION_TYPES.include?(type)
          raise(ArgumentError, "Invalid type: #{type.inspect}. Valid types: #{SymmetricEncryption::COERCION_TYPES.inspect}")
        end

        super()
        @random_iv           = random_iv
        @compress            = compress
        @encrypted_type      = type
        @version             = version
        @rails_type          = RAILS_CAST_TYPES[type]&.new
        @multiparameter_type = MULTIPARAMETER_TYPES[type]&.new
      end

      def deserialize(value)
        return if value.nil?

        SymmetricEncryption.decrypt(value, type: encrypted_type, version: version)
      end

      def serialize(value)
        value = cast(value)
        return if value.nil?

        SymmetricEncryption.encrypt(
          value,
          type:      encrypted_type,
          compress:  compress,
          random_iv: random_iv,
          version:   version
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

      # A multiparameter assignment was constructed by Active Record from the submitted form
      # fields, so it did not come from the user as it stands. Validations therefore report on the
      # cast value rather than on `*_before_type_cast`, as for an unencrypted date or time.
      def value_constructed_by_mass_assignment?(value)
        multiparameter?(value)
      end

      private

      def multiparameter?(value)
        !multiparameter_type.nil? && value.is_a?(::Hash)
      end

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
          # Only dates and times accept a Hash, and only as a multiparameter assignment. Coercible
          # would turn it into the current date or time, since it looks for the keys :year, :month
          # and :day and falls back to `Time.now` for each one that it does not find.
          value = multiparameter_type.cast(value) if multiparameter?(value)
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

      attr_reader :random_iv, :compress, :encrypted_type, :version, :rails_type, :multiparameter_type
    end
  end
end
