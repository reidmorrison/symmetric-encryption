module SymmetricEncryption
  class EncryptedStringType < ActiveRecord::Type::String
    def initialize(encrypt_params: {}, decrypt_params: {})
      @encrypt_params = encrypt_params
      @decrypt_params = decrypt_params
    end

    def deserialize(value)
      SymmetricEncryption.decrypt(value, decrypt_params) if value
    end

    def serialize(value)
      SymmetricEncryption.encrypt(value, encrypt_params) if value
    end

    private

    attr_reader :decrypt_params, :encrypt_params
  end
end
