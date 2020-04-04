require "openssl"
module SymmetricEncryption
  # DEPRECATED - Internal use only
  class RSAKey
    # DEPRECATED - Internal use only
    def initialize(private_rsa_key)
      @rsa = OpenSSL::PKey::RSA.new(private_rsa_key)
    end

    # DEPRECATED - Internal use only
    def encrypt(key)
      rsa.public_encrypt(key)
    end

    # DEPRECATED - Internal use only
    def decrypt(encrypted_key)
      rsa.private_decrypt(encrypted_key)
    end

    private

    attr_reader :rsa
  end
end
