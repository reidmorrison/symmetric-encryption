require 'base64'
require 'openssl'
require 'zlib'

module Symmetric

  # Encrypt using 256 Bit AES CBC symmetric key and initialization vector
  # The symmetric key is protected using the private key below and must
  # be distributed separately from the application
  class Encryption

    # Binary encrypted data includes this magic header so that we can quickly
    # identify binary data versus base64 encoded data that does not have this header
    unless defined? MAGIC_HEADER
      MAGIC_HEADER = '@EnC'
      MAGIC_HEADER_SIZE = MAGIC_HEADER.size
    end

    # Set the Symmetric Cipher to be used
    def self.cipher=(cipher)
      @@cipher = cipher
    end

    # Returns the Symmetric Cipher being used
    def self.cipher
      @@cipher
    end

    # Set the Symmetric Key to use for encryption and decryption
    def self.key=(key)
      @@key = key
    end

    # Set the Initialization Vector to use with Symmetric Key
    def self.iv=(iv)
      @@iv = iv
    end

    # Defaults
    @@key = nil
    @@iv = nil

    # Load the Encryption Configuration from a YAML file
    #  filename: Name of file to read.
    #        Mandatory for non-Rails apps
    #        Default: Rails.root/config/symmetry.yml
    def self.load!(filename=nil, environment=nil)
      config = YAML.load_file(filename || File.join(Rails.root, "config", "symmetric-encryption.yml"))[environment || Rails.env]
      self.cipher = config['cipher'] || 'aes-256-cbc'
      symmetric_key = config['symmetric_key']
      symmetric_iv = config['symmetric_iv']

      # Hard coded symmetric_key?
      if symmetric_key
        self.key = symmetric_key
        self.iv = symmetric_iv
      else
        load_keys(config['key_filename'], config['iv_filename'], config['private_key'])
      end

    end

    # Load the symmetric key to use for encrypting and decrypting data
    # Call from environment.rb before calling encrypt or decrypt
    #
    # private_key: Key used to unlock file containing the actual symmetric key
    def self.load_keys(key_filename, iv_filename, private_key)
      # Load Encrypted Symmetric keys
      encrypted_key = File.read(key_filename)
      encrypted_iv = File.read(iv_filename)

      # Decrypt Symmetric Key
      rsa = OpenSSL::PKey::RSA.new(private_key)
      @@key = rsa.private_decrypt(encrypted_key)
      @@iv = rsa.private_decrypt(encrypted_iv)
      nil
    end

    # Generate new random keys for use with this Encryption library
    #
    # Creates:
    #   2048 bit Private Key private.key
    #   2048 bit Public Key public.key
    #
    #   Symmetric Key .key
    #   and initilization vector .iv
    #       which is encrypted with the above Public key
    #
    # Note: Existing files will be overwritten
    def self.generate_key_files(symmetric_keys_path='.', rsa_keys_path='.', cipher='aes-256-cbc')
      # Generate Asymmetric key pair
      new_key = OpenSSL::PKey::RSA.generate(2048)
      # To ensure compatibility with C openssl code, remove RSA from pub file headers
      pub_key = new_key.public_key.export.gsub('RSA PUBLIC','PUBLIC')
      File.open(File.join(rsa_keys_path, 'public.key'), 'w') {|file| file.write(pub_key)}
      File.open(File.join(rsa_keys_path, 'private.key'), 'w') {|file| file.write(new_key.to_pem)}

      # Generate Symmetric Key
      cipher = OpenSSL::Cipher::Cipher.new(cipher)
      cipher.encrypt
      @@key = cipher.random_key
      @@iv = cipher.random_iv

      # Save symmetric key after encrypting it with the private asymmetric key
      File.open(File.join(symmetric_keys_path, '.key'), 'wb') {|file| file.write( OpenSSL::PKey::RSA.new(new_key.public_key).public_encrypt(@@key) ) }
      File.open(File.join(symmetric_keys_path, '.iv'), 'wb') {|file| file.write( OpenSSL::PKey::RSA.new(new_key.public_key).public_encrypt(@@iv) ) }
      Rails.logger.info("Generated new Private, Public and Symmetric Key for encryption. Please copy #{filename} to the other servers.")
    end

    # Generate a 22 character random password
    def self.random_password
      Base64.encode64(OpenSSL::Cipher::Cipher.new('aes-128-cbc').random_key)[0..-4]
    end

    # AES Symmetric Decryption of supplied string
    #  Returns decrypted string
    #  Returns nil if the supplied str is nil
    #  Returns "" if it is a string and it is empty
    def self.decrypt(str)
      return str if str.nil? || (str.is_a?(String) && str.empty?)
      self.crypt(:decrypt, Base64.decode64(str))
    end

    # AES Symmetric Encryption of supplied string
    #  Returns result as a Base64 encoded string
    #  Returns nil if the supplied str is nil
    #  Returns "" if it is a string and it is empty
    def self.encrypt(str)
      return str if str.nil? || (str.is_a?(String) && str.empty?)
      Base64.encode64(self.crypt(:encrypt, str))
    end

    # Invokes decrypt
    #  Returns decrypted String
    #  Return nil if it fails to decrypt a String
    #
    # Useful for example when decoding passwords encrypted using a key from a
    # different environment. I.e. We cannot decode production passwords
    # in the test or development environments but still need to be able to load
    # YAML config files that contain encrypted development and production passwords
    def self.try_decrypt(str)
      self.decrypt(str) rescue nil
    end

    # AES Symmetric Encryption of supplied string
    #  Returns result as a binary encrypted string
    #  Returns nil if the supplied str is nil or empty
    # Parameters
    #  compress => Whether to compress the supplied string using zip before
    #              encrypting
    #              true | false
    #              Default false
    def self.encrypt_binary(str, compress=false)
      return nil if str.nil? || (str.is_a?(String) && str.empty?)
      # Bit Layout
      # 15    => Compressed?
      # 0..14 => Version number of encryption key/algorithm currently 0
      flags = 0 # Same as 0b0000_0000_0000_0000
      # If the data is to be compressed before being encrypted, set the flag and
      # compress using zlib. Only compress if data is greater than 15 chars
      str = str.to_s unless str.is_a?(String)
      if compress && str.length > 15
        flags |= 0b1000_0000_0000_0000
        begin
          ostream = StringIO.new
          gz = Zlib::GzipWriter.new(ostream)
          gz.write(str)
          str = ostream.string
        ensure
          gz.close
        end
      end
      return nil unless encrypted = self.crypt(:encrypt, str)
      # Resulting buffer consists of:
      #   '@EnC'
      #   unsigned short (32 bits) in little endian format for flags above
      #   'actual encrypted buffer data'
      "#{MAGIC_HEADER}#{[flags].pack('v')}#{encrypted}"
    end

    # AES Symmetric Decryption of supplied Binary string
    #  Returns decrypted string
    #  Returns nil if the supplied str is nil
    #  Returns "" if it is a string and it is empty
    def self.decrypt_binary(str)
      return str if str.nil? || (str.is_a?(String) && str.empty?)
      str = str.to_s unless str.is_a?(String)
      encrypted = if str.starts_with? MAGIC_HEADER
        # Remove header and extract flags
        header, flags = str.unpack(@@unpack ||= "A#{MAGIC_HEADER_SIZE}v")
        # Uncompress if data is compressed and remove header
        if flags & 0b1000_0000_0000_0000
          begin
            gz = Zlib::GzipReader.new(StringIO.new(str[MAGIC_HEADER_SIZE,-1]))
            gz.read
          ensure
            gz.close
          end
        else
          str[MAGIC_HEADER_SIZE,-1]
        end
      else
        Base64.decode64(str)
      end
      self.crypt(:decrypt, encrypted)
    end

    protected

    def self.crypt(cipher_method, string) #:nodoc:
      openssl_cipher = OpenSSL::Cipher::Cipher.new(self.cipher)
      openssl_cipher.send(cipher_method)
      raise "Encryption.key must be set before calling Encryption encrypt or decrypt" unless @@key
      openssl_cipher.key = @@key
      openssl_cipher.iv = @@iv if @@iv
      result = openssl_cipher.update(string.to_s)
      result << openssl_cipher.final
    end

  end
end