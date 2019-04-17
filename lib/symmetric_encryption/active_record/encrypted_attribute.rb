module SymmetricEncryption
  module ActiveRecord
    class EncryptedAttribute < ::ActiveRecord::Type::String
      attr_reader :random_iv, :compress, :type

      def initialize(random_iv: true, compress: false, type: :string)
        @random_iv = random_iv
        @compress  = compress
        @type      = type
      end

      def deserialize(value)
        SymmetricEncryption.decrypt(value, type: type) if value
      end

      def serialize(value)
        SymmetricEncryption.encrypt(value, type: type, compress: compress, random_iv: random_iv) if value
      end
    end
  end
end
