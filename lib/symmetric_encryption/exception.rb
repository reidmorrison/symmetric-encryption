module SymmetricEncryption
  # Exceptions created by SymmetricEncryption
  class Error < StandardError
  end

  # Exceptions when working with Ciphers
  class CipherError < Error
  end

  # Exceptions when trying to use the keys before they have been configured
  class ConfigError < Error
  end
end
