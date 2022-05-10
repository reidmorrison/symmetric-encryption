module SymmetricEncryption
  module ActiveRecord
    class EncryptedAttribute < ::ActiveModel::Type::String
      def initialize(random_iv: true, compress: false, type: :string)
        @random_iv      = random_iv
        @compress       = compress
        @encrypted_type = type
      end

      def deserialize(value)
        return if value.nil?

        SymmetricEncryption.decrypt(value, type: encrypted_type)
      end

      def serialize(value)
        return if value.nil?

        SymmetricEncryption.encrypt(
          value,
          type:      encrypted_type,
          compress:  compress,
          random_iv: random_iv
        )
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
