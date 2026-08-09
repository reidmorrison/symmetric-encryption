# The key, iv and encrypted data are handled in their raw form, with no encoding.
module SymmetricEncryption
  # A symmetric key and its iv, and the OpenSSL cipher they belong to.
  #
  # Thin wrapper over OpenSSL. A Key can be the data encryption key that a `Cipher` encrypts with,
  # or a key encrypting key that decrypts another key, which is how `Keystore.read_key` walks a
  # chain of nested `key_encrypting_key` entries in the configuration file.
  class Key
    attr_reader :key, :iv, :cipher_name

    # Returns [String] the supplied key material as a binary string, after verifying that it is
    # exactly the number of bytes that `cipher_name` requires.
    #
    # OpenSSL only checks the length when the key is used, and its message, `key must be 32 bytes`,
    # names neither the cipher nor where the key came from. The usual cause is a key that was hex or
    # base64 encoded so that it could be stored in `symmetric-encryption.yml`, leaving it with the
    # right number of characters and the wrong number of bytes.
    def self.binary!(value, length:, cipher_name:, name:)
      binary = value.to_s.b
      return binary if binary.length == length

      raise(
        ArgumentError,
        "The #{name} supplied for cipher_name: #{cipher_name.inspect} must be exactly #{length} bytes, " \
        "but is #{binary.length} bytes. The #{name} is raw binary data, not text, so a #{name} that was " \
        "hex or base64 encoded in order to store it in symmetric-encryption.yml has to be decoded first. " \
        "Supply it base64 encoded with the YAML binary tag to have YAML decode it: `#{name}: !!binary |`, " \
        "followed by the base64 encoded #{name} on the next line."
      )
    end

    def initialize(key: :random, iv: :random, cipher_name: "aes-256-cbc")
      openssl_cipher = ::OpenSSL::Cipher.new(cipher_name)
      key            = openssl_cipher.random_key if key == :random
      iv             = openssl_cipher.random_iv if iv == :random

      @key         = self.class.binary!(key, length: openssl_cipher.key_len, cipher_name: cipher_name, name: "key")
      @iv          = iv && self.class.binary!(iv, length: openssl_cipher.iv_len, cipher_name: cipher_name, name: "iv")
      @cipher_name = cipher_name
    end

    # Returns [String] the encrypted string.
    #
    # With an authenticated cipher, such as `aes-256-gcm`, the auth tag is appended to the
    # encrypted data, since a Key has no header to carry it in. `SymmetricEncryption::ChunkedStream`
    # writes its chunks the same way.
    def encrypt(string)
      return if string.nil?

      string = string.to_s
      return string if string.empty?

      # Creates a new OpenSSL::Cipher with every call so that this key instance is thread-safe.
      openssl_cipher = ::OpenSSL::Cipher.new(cipher_name)
      openssl_cipher.encrypt
      openssl_cipher.key = key
      openssl_cipher.iv  = iv

      result = openssl_cipher.update(string)
      result << openssl_cipher.final
      result << openssl_cipher.auth_tag(Header::AUTH_TAG_SIZE) if openssl_cipher.authenticated?
      result
    end

    # Returns [String] the decrypted string.
    #
    # Raises OpenSSL::Cipher::CipherError when an authenticated cipher's auth tag does not match,
    # which is what detects a key file that has been tampered with.
    def decrypt(encrypted_string)
      return if encrypted_string.nil?

      # Work against a binary copy rather than re-encoding the caller's string in place.
      encrypted_string = encrypted_string.to_s
      encrypted_string = encrypted_string.b unless encrypted_string.encoding == SymmetricEncryption::BINARY_ENCODING
      return encrypted_string if encrypted_string.empty?

      # Creates a new OpenSSL::Cipher with every call so that this key instance is thread-safe.
      openssl_cipher = ::OpenSSL::Cipher.new(cipher_name)
      openssl_cipher.decrypt
      openssl_cipher.key = key
      openssl_cipher.iv  = iv
      encrypted_string   = extract_auth_tag!(openssl_cipher, encrypted_string) if openssl_cipher.authenticated?

      result = openssl_cipher.update(encrypted_string)
      result << openssl_cipher.final
    end

    private

    # Returns [String] the encrypted data with the trailing auth tag removed, after handing the tag
    # to the cipher. See `#encrypt` for where it is appended.
    def extract_auth_tag!(openssl_cipher, encrypted_string)
      size = Header::AUTH_TAG_SIZE
      if encrypted_string.bytesize <= size
        raise(
          SymmetricEncryption::CipherError,
          "The encrypted key is #{encrypted_string.bytesize} bytes, too short to hold its #{size} byte auth tag. " \
          "Cipher #{cipher_name.inspect} is an authenticated cipher, so the key it encrypted carries one."
        )
      end

      openssl_cipher.auth_tag = encrypted_string.byteslice(-size, size)
      encrypted_string.byteslice(0, encrypted_string.bytesize - size)
    end
  end
end
