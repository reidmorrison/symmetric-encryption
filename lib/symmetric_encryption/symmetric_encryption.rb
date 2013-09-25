require 'base64'
require 'openssl'
require 'zlib'
require 'yaml'
require 'erb'

# Encrypt using 256 Bit AES CBC symmetric key and initialization vector
# The symmetric key is protected using the private key below and must
# be distributed separately from the application
module SymmetricEncryption

  # Defaults
  @@cipher = nil
  @@secondary_ciphers = []
  @@select_cipher = nil

  # Set the Primary Symmetric Cipher to be used
  #
  # Example: For testing purposes the following test cipher can be used:
  #
  #   SymmetricEncryption.cipher = SymmetricEncryption::Cipher.new(
  #     :key    => '1234567890ABCDEF1234567890ABCDEF',
  #     :iv     => '1234567890ABCDEF',
  #     :cipher => 'aes-128-cbc'
  #   )
  def self.cipher=(cipher)
    raise "Cipher must be similar to SymmetricEncryption::Ciphers" unless cipher.nil? || (cipher.respond_to?(:encrypt) && cipher.respond_to?(:decrypt))
    @@cipher = cipher
  end

  # Returns the Primary Symmetric Cipher being used
  # If a version is supplied
  #   Returns the primary cipher if no match was found and version == 0
  #   Returns nil if no match was found and version != 0
  def self.cipher(version = nil)
    raise "Call SymmetricEncryption.load! or SymmetricEncryption.cipher= prior to encrypting or decrypting data" unless @@cipher
    return @@cipher if version.nil? || (@@cipher.version == version)
    secondary_ciphers.find {|c| c.version == version} || (@@cipher if version == 0)
  end

  # Set the Secondary Symmetric Ciphers Array to be used
  def self.secondary_ciphers=(secondary_ciphers)
    raise "secondary_ciphers must be a collection" unless secondary_ciphers.respond_to? :each
    secondary_ciphers.each do |cipher|
      raise "secondary_ciphers can only consist of SymmetricEncryption::Ciphers" unless cipher.respond_to?(:encrypt) && cipher.respond_to?(:decrypt)
    end
    @@secondary_ciphers = secondary_ciphers
  end

  # Returns the Primary Symmetric Cipher being used
  def self.secondary_ciphers
    @@secondary_ciphers
  end

  # AES Symmetric Decryption of supplied string
  #  Returns decrypted string
  #  Returns nil if the supplied str is nil
  #  Returns "" if it is a string and it is empty
  #
  #  Parameters
  #    str
  #      Encrypted string to decrypt
  #    version
  #      Specify which cipher version to use if no header is present on the
  #      encrypted string
  #
  #  If the supplied string has an encryption header then the cipher matching
  #  the version number in the header will be used to decrypt the string
  #
  #  When no header is present in the encrypted data, a custom Block/Proc can
  #  be supplied to determine which cipher to use to decrypt the data.
  #  see #cipher_selector=
  #
  # Raises: OpenSSL::Cipher::CipherError when 'str' was not encrypted using
  # the primary key and iv
  #
  # NOTE: #decrypt will _not_ attempt to use a secondary cipher if it fails
  #       to decrypt the current string. This is because in a very small
  #       yet significant number of cases it is possible to decrypt data using
  #       the incorrect key. Clearly the data returned is garbage, but it still
  #       successfully returns a string of data
  def self.decrypt(encrypted_and_encoded_string, version=nil)
    raise "Call SymmetricEncryption.load! or SymmetricEncryption.cipher= prior to encrypting or decrypting data" unless @@cipher
    return encrypted_and_encoded_string if encrypted_and_encoded_string.nil? || (encrypted_and_encoded_string == '')

    str = encrypted_and_encoded_string.to_s

    # Decode before decrypting supplied string
    decoded = @@cipher.decode(str)
    return unless decoded
    return decoded if decoded.empty?

    decrypted = if header = Cipher.parse_header!(decoded)
      header.decryption_cipher.binary_decrypt(decoded, header)
    else
      # Use cipher_selector if present to decide which cipher to use
      c = @@select_cipher.nil? ? cipher(version) : @@select_cipher.call(str, decoded)
      c.binary_decrypt(decoded)
    end

    if defined?(Encoding)
      # Try to force result to UTF-8 encoding, but if it is not valid, force it back to Binary
      unless decrypted.force_encoding(SymmetricEncryption::UTF8_ENCODING).valid_encoding?
        decrypted.force_encoding(SymmetricEncryption::BINARY_ENCODING)
      end
    end
    decrypted
  end

  # AES Symmetric Encryption of supplied string
  #  Returns result as a Base64 encoded string
  #  Returns nil if the supplied str is nil
  #  Returns "" if it is a string and it is empty
  #
  # Parameters
  #   str [String]
  #     String to be encrypted. If str is not a string, #to_s will be called on it
  #     to convert it to a string
  #
  #   random_iv [true|false]
  #     Whether the encypted value should use a random IV every time the
  #     field is encrypted.
  #     It is recommended to set this to true where feasible. If the encrypted
  #     value could be used as part of a SQL where clause, or as part
  #     of any lookup, then it must be false.
  #     Setting random_iv to true will result in a different encrypted output for
  #     the same input string.
  #     Note: Only set to true if the field will never be used as part of
  #       the where clause in an SQL query.
  #     Note: When random_iv is true it will add a 8 byte header, plus the bytes
  #       to store the random IV in every returned encrypted string, prior to the
  #       encoding if any.
  #     Default: false
  #     Highly Recommended where feasible: true
  #
  #   compress [true|false]
  #     Whether to compress str before encryption
  #     Should only be used for large strings since compression overhead and
  #     the overhead of adding the 'magic' header may exceed any benefits of
  #     compression
  #     Note: Adds a 6 byte header prior to encoding, only if :random_iv is false
  #     Default: false
  def self.encrypt(str, random_iv=false, compress=false)
    raise "Call SymmetricEncryption.load! or SymmetricEncryption.cipher= prior to encrypting or decrypting data" unless @@cipher

    # Encrypt and then encode the supplied string
    @@cipher.encrypt(str, random_iv, compress)
  end

  # Invokes decrypt
  #  Returns decrypted String
  #  Return nil if it fails to decrypt a String
  #
  # Useful for example when decoding passwords encrypted using a key from a
  # different environment. I.e. We cannot decode production passwords
  # in the test or development environments but still need to be able to load
  # YAML config files that contain encrypted development and production passwords
  #
  # WARNING: It is possible to decrypt data using the wrong key, so the value
  #          returned should not be relied upon
  def self.try_decrypt(str)
    raise "Call SymmetricEncryption.load! or SymmetricEncryption.cipher= prior to encrypting or decrypting data" unless @@cipher
    begin
      decrypt(str)
    rescue OpenSSL::Cipher::CipherError
      nil
    end
  end

  # Returns [true|false] as to whether the data could be decrypted
  #   Parameters:
  #     encrypted_data: Encrypted string
  #
  # WARNING: This method can only be relied upon if the encrypted data includes the
  #          symmetric encryption header. In some cases data decrypted using the
  #          wrong key will decrypt and return garbage
  def self.encrypted?(encrypted_data)
    raise "Call SymmetricEncryption.load! or SymmetricEncryption.cipher= prior to encrypting or decrypting data" unless @@cipher

    # For now have to decrypt it fully
    result = try_decrypt(encrypted_data)
    !(result.nil? || result == '')
  end

  # When no header is present in the encrypted data, this custom Block/Proc is
  # used to determine which cipher to use to decrypt the data.
  #
  # The Block must return a valid cipher
  #
  # Parameters
  #   encoded_str
  #     The original encoded string
  #
  #   decoded_str
  #     The string after being decoded using the global encoding
  #
  # NOTE: Do _not_ attempt to use a secondary cipher if the previous fails
  #       to decrypt due to an OpenSSL::Cipher::CipherError exception.
  #       This is because in a very small, yet significant number of cases it is
  #       possible to decrypt data using the incorrect key.
  #       Clearly the data returned is garbage, but it still successfully
  #       returns a string of data
  #
  # Example:
  #   SymmetricEncryption.select_cipher do |encoded_str, decoded_str|
  #     # Use cipher version 0 if the encoded string ends with "\n" otherwise
  #     # use the current default cipher
  #     encoded_str.end_with?("\n") ? SymmetricEncryption.cipher(0) : SymmetricEncryption.cipher
  #   end
  def self.select_cipher(&block)
    @@select_cipher = block ? block : nil
  end

  # Load the Encryption Configuration from a YAML file
  #  filename:
  #    Name of file to read.
  #        Mandatory for non-Rails apps
  #        Default: Rails.root/config/symmetric-encryption.yml
  #  environment:
  #    Which environments config to load. Usually: production, development, etc.
  #    Default: Rails.env
  def self.load!(filename=nil, environment=nil)
    ciphers = read_config(filename, environment)
    @@cipher = ciphers.shift
    @@secondary_ciphers = ciphers
    true
  end

  # Generate new random symmetric keys for use with this Encryption library
  #
  # Note: Only the current Encryption key settings are used
  #
  # Creates Symmetric Key .key
  #   and initilization vector .iv
  #       which is encrypted with the above Public key
  #
  # Existing key files will be renamed if present
  def self.generate_symmetric_key_files(filename=nil, environment=nil)
    config_filename = filename || File.join(Rails.root, "config", "symmetric-encryption.yml")
    config = YAML.load(ERB.new(File.new(config_filename).read).result)[environment || Rails.env]

    # RSA key to decrypt key files
    private_rsa_key = config.delete('private_rsa_key')
    raise "The configuration file must contain a 'private_rsa_key' parameter to generate symmetric keys" unless private_rsa_key
    rsa_key = OpenSSL::PKey::RSA.new(private_rsa_key)

    # Check if config file contains 1 or multiple ciphers
    ciphers = config.delete('ciphers')
    cfg = ciphers.nil? ? config : ciphers.first

    # Convert keys to symbols
    cipher_cfg = {}
    cfg.each_pair{|k,v| cipher_cfg[k.to_sym] = v}

    cipher_name = cipher_cfg[:cipher_name] || cipher_cfg[:cipher]

    # Generate a new Symmetric Key pair
    iv_filename = cipher_cfg[:iv_filename]
    key_pair = SymmetricEncryption::Cipher.random_key_pair(cipher_name || 'aes-256-cbc')

    if key_filename = cipher_cfg[:key_filename]
      # Save symmetric key after encrypting it with the private RSA key, backing up existing files if present
      File.rename(key_filename, "#{key_filename}.#{Time.now.to_i}") if File.exist?(key_filename)
      File.open(key_filename, 'wb') {|file| file.write( rsa_key.public_encrypt(key_pair[:key]) ) }
      puts("Generated new Symmetric Key for encryption. Please copy #{key_filename} to the other web servers in #{environment}.")
    elsif !cipher_cfg[:key]
      key = rsa_key.public_encrypt(key_pair[:key])
      puts "Generated new Symmetric Key for encryption. Set the KEY environment variable in #{environment} to:"
      puts ::Base64.encode64(key)
    end

    if iv_filename
      File.rename(iv_filename, "#{iv_filename}.#{Time.now.to_i}") if File.exist?(iv_filename)
      File.open(iv_filename, 'wb') {|file| file.write( rsa_key.public_encrypt(key_pair[:iv]) ) }
      puts("Generated new Symmetric Key for encryption. Please copy #{iv_filename} to the other web servers in #{environment}.")
    elsif !cipher_cfg[:iv]
      iv = rsa_key.public_encrypt(key_pair[:iv])
      puts "Generated new Symmetric Key for encryption. Set the IV environment variable in #{environment} to:"
      puts ::Base64.encode64(key)
    end
  end

  # Generate a 22 character random password
  def self.random_password
    Base64.encode64(OpenSSL::Cipher.new('aes-128-cbc').random_key)[0..-4].strip
  end

  # Binary encrypted data includes this magic header so that we can quickly
  # identify binary data versus base64 encoded data that does not have this header
  unless defined? MAGIC_HEADER
    MAGIC_HEADER = '@EnC'
    MAGIC_HEADER_SIZE = MAGIC_HEADER.size
    MAGIC_HEADER_UNPACK = "a#{MAGIC_HEADER_SIZE}v"
  end

  protected

  # Returns [Array(SymmetricEncrytion::Cipher)] ciphers specified in the configuration file
  #
  # Read the configuration from the YAML file and return in the latest format
  #
  #  filename:
  #    Name of file to read.
  #        Mandatory for non-Rails apps
  #        Default: Rails.root/config/symmetric-encryption.yml
  #  environment:
  #    Which environments config to load. Usually: production, development, etc.
  def self.read_config(filename=nil, environment=nil)
    config_filename = filename || File.join(Rails.root, "config", "symmetric-encryption.yml")
    config = YAML.load(ERB.new(File.new(config_filename).read).result)[environment || Rails.env]

    # RSA key to decrypt key files
    private_rsa_key = config.delete('private_rsa_key')

    if ciphers = config.delete('ciphers')
      ciphers.collect {|cipher_conf| cipher_from_config(cipher_conf, private_rsa_key)}
    else
      [cipher_from_config(config, private_rsa_key)]
    end
  end

  # Returns an instance of SymmetricEncryption::Cipher created from
  # the supplied configuration and optional rsa_encryption_key
  #
  # Raises an Exception on failure
  #
  # Parameters:
  #   cipher_conf Hash:
  #     :cipher_name
  #       Encryption cipher name for the symmetric encryption key
  #
  #     :version
  #       The version number of this cipher
  #       Default: 0
  #
  #     :encoding [Symbol]
  #       Encoding to use after encrypting with this cipher
  #
  #     :always_add_header
  #       Whether to always include the header when encrypting data.
  #       Highly recommended to set this value to true.
  #       Increases the length of the encrypted data by 6 bytes, but makes
  #       migration to a new key trivial
  #       Default: false
  #
  #     :key
  #       The actual key to use for encryption/decryption purposes
  #
  #     :key_filename
  #       Name of file containing symmetric key encrypted using the public
  #       key from the private_rsa_key
  #
  #     :encrypted_key
  #       Symmetric key encrypted using the public key from the private_rsa_key
  #
  #     :iv
  #       Optional: The actual iv to use for encryption/decryption purposes
  #
  #     :encrypted_iv
  #       Initialization vector encrypted using the public key from the private_rsa_key
  #
  #     :iv_filename
  #       Optional: Name of file containing symmetric key initialization vector
  #       encrypted using the public key from the private_rsa_key
  #
  #   private_rsa_key [String]
  #     RSA Key used to decrypt key and iv as applicable
  def self.cipher_from_config(cipher_conf, private_rsa_key=nil)
    config = {}
    cipher_conf.each_pair{|k,v| config[k.to_sym] = v}

    # To decrypt encrypted key or iv files
    rsa = OpenSSL::PKey::RSA.new(private_rsa_key) if private_rsa_key

    # Load Encrypted Symmetric keys
    if key_filename = config.delete(:key_filename)
      raise "Missing mandatory config parameter :private_rsa_key when :key_filename is supplied" unless rsa
      encrypted_key = begin
        File.read(key_filename, :open_args => ['rb'])
      rescue Errno::ENOENT
        puts "\nSymmetric Encryption key file: '#{key_filename}' not found or readable."
        puts "To generate the keys for the first time run: rails generate symmetric_encryption:new_keys\n\n"
        return
      end
      config[:key] = rsa.private_decrypt(encrypted_key)
    end

    if iv_filename = config.delete(:iv_filename)
      raise "Missing mandatory config parameter :private_rsa_key when :iv_filename is supplied" unless rsa
      encrypted_iv = begin
        File.read(iv_filename, :open_args => ['rb']) if iv_filename
      rescue Errno::ENOENT
        puts "\nSymmetric Encryption initialization vector file: '#{iv_filename}' not found or readable."
        puts "To generate the keys for the first time run: rails generate symmetric_encryption:new_keys\n\n"
        return
      end
      config[:iv] = rsa.private_decrypt(encrypted_iv)
    end

    if encrypted_key = config.delete(:encrypted_key)
      raise "Missing mandatory config parameter :private_rsa_key when :encrypted_key is supplied" unless rsa
      # Decode value first using encoding specified
      encrypted_key = ::Base64.decode64(encrypted_key)
      config[:key] = rsa.private_decrypt(encrypted_key)
    end

    if encrypted_iv = config.delete(:encrypted_iv)
      raise "Missing mandatory config parameter :private_rsa_key when :encrypted_iv is supplied" unless rsa
      # Decode value first using encoding specified
      encrypted_iv = ::Base64.decode64(encrypted_iv)
      config[:iv] = rsa.private_decrypt(encrypted_iv)
    end

    # Backward compatibility
    if old_key_name_cipher = config.delete(:cipher)
      config[:cipher_name] = old_key_name_cipher
    end

    # Decrypt Symmetric Keys
    Cipher.new(config)
  end

  # With Ruby 1.9 strings have encodings
  if defined?(Encoding)
    BINARY_ENCODING = Encoding.find("binary")
    UTF8_ENCODING = Encoding.find("UTF-8")
  end

end