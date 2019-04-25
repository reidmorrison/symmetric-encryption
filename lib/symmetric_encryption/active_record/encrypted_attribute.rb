module SymmetricEncryption
  module ActiveRecord
    class EncryptedAttribute < ::ActiveRecord::Type::String
      def initialize(random_iv: true, compress: false, type: :string)
        @random_iv      = random_iv
        @compress       = compress
        @encrypted_type = encrypted_type
      end

      def deserialize(value)
        SymmetricEncryption.decrypt(value, type: encrypted_type) if value
      end

      def serialize(value)
        SymmetricEncryption.encrypt(value, type: encrypted_type, compress: compress, random_iv: random_iv) if value
      end

      private

      attr_reader :random_iv, :compress, :encrypted_type
    end
  end
end
