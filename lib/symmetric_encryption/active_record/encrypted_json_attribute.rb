module SymmetricEncryption
  module ActiveRecord
    class EncryptedJsonAttribute < ::ActiveRecord::Type::Json
      def initialize(random_iv: true, compress: false, type: :json)
        @random_iv      = random_iv
        @compress       = compress
        @encrypted_type = type

        unless type == :json
          raise(ArgumentError, "Invalid type: #{type.inspect}. :json is valid type")
        end
      end

      def deserialize(value)
        return if value.nil?

        value = super(value)
        SymmetricEncryption.decrypt(value, type: encrypted_type)
      end

      def serialize(value)
        return if value.nil?

        value = SymmetricEncryption.encrypt(
          value,
          type:      encrypted_type,
          compress:  compress,
          random_iv: random_iv
        )
        super(value)
      end

      def changed_in_place?(raw_old_value, new_value)
        deserialize(raw_old_value) != new_value
      end

      private

      # Symmetric Encryption uses coercible gem to handle casting
      def cast_value(value)
        value
      end

      attr_reader :random_iv, :compress, :encrypted_type
    end
  end
end
