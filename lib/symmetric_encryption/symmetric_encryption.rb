require 'base64'
require 'openssl'
require 'zlib'
require 'yaml'

# Encrypt using 256 Bit AES CBC symmetric key and initialization vector
# The symmetric key is protected using the private key below and must
# be distributed separately from the application
module SymmetricEncryption

  # Defaults
  @@cipher = nil
  @@secondary_ciphers = []

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
  # Note: If secondary ciphers are supplied in the configuration file the
  #   first key will be used to decrypt 'str'. If it fails each cipher in the
  #   order supplied will be tried.
  #   It is slow to try each cipher in turn, so should be used during migrations
  #   only
  #
  # Raises: OpenSSL::Cipher::CipherError when 'str' was not encrypted using
  # the supplied key and iv
  #
  def self.decrypt(str)
    raise "Call SymmetricEncryption.load! or SymmetricEncryption.cipher= prior to encrypting or decrypting data" unless @@cipher

    # Decode and then decrypt supplied string
    begin
      @@cipher.decrypt(str)
    rescue OpenSSL::Cipher::CipherError => exc
      @@secondary_ciphers.each do |cipher|
        begin
          return cipher.decrypt(str)
        rescue OpenSSL::Cipher::CipherError
        end
      end
      raise exc
    end
  end

  # AES Symmetric Encryption of supplied string
  #  Returns result as a Base64 encoded string
  #  Returns nil if the supplied str is nil
  #  Returns "" if it is a string and it is empty
  def self.encrypt(str)
    raise "Call SymmetricEncryption.load! or SymmetricEncryption.cipher= prior to encrypting or decrypting data" unless @@cipher

    # Encrypt and then encode the supplied string
    @@cipher.encrypt(str)
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
  def self.encrypted?(encrypted_data)
    raise "Call SymmetricEncryption.load! or SymmetricEncryption.cipher= prior to encrypting or decrypting data" unless @@cipher

    # For now have to decrypt it fully
    result = try_decrypt(encrypted_data)
    !(result.nil? || result == '')
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
    config = read_config(filename, environment)

    # Check for hard coded key, iv and cipher
    if config[:key]
      @@cipher = Cipher.new(config)
      @@secondary_ciphers = []
    else
      private_rsa_key = config[:private_rsa_key]
      @@cipher, *@@secondary_ciphers = config[:ciphers].collect do |cipher_conf|
        cipher_from_encrypted_files(private_rsa_key, cipher_conf)
      end
    end

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
    config = read_config(filename, environment)
    cipher_cfg = config[:ciphers].first
    key_filename = cipher_cfg[:key_filename]
    iv_filename = cipher_cfg[:iv_filename]
    cipher = cipher_cfg[:cipher]

    raise "The configuration file must contain a 'private_rsa_key' parameter to generate symmetric keys" unless config[:private_rsa_key]
    rsa_key = OpenSSL::PKey::RSA.new(config[:private_rsa_key])

    # Generate a new Symmetric Key pair
    key_pair = SymmetricEncryption::Cipher.random_key_pair(cipher || 'aes-256-cbc', !iv_filename.nil?)

    # Save symmetric key after encrypting it with the private RSA key, backing up existing files if present
    File.rename(key_filename, "#{key_filename}.#{Time.now.to_i}") if File.exist?(key_filename)
    File.open(key_filename, 'wb') {|file| file.write( rsa_key.public_encrypt(key_pair[:key]) ) }

    if iv_filename
      File.rename(iv_filename, "#{iv_filename}.#{Time.now.to_i}") if File.exist?(iv_filename)
      File.open(iv_filename, 'wb') {|file| file.write( rsa_key.public_encrypt(key_pair[:iv]) ) }
    end
    puts("Generated new Symmetric Key for encryption. Please copy #{key_filename} and #{iv_filename} to the other web servers in #{environment}.")
  end

  # Generate a 22 character random password
  def self.random_password
    Base64.encode64(OpenSSL::Cipher.new('aes-128-cbc').random_key)[0..-4]
  end

  # Binary encrypted data includes this magic header so that we can quickly
  # identify binary data versus base64 encoded data that does not have this header
  unless defined? MAGIC_HEADER
    MAGIC_HEADER = '@EnC'
    MAGIC_HEADER_SIZE = MAGIC_HEADER.size
    MAGIC_HEADER_UNPACK = "a#{MAGIC_HEADER_SIZE}v"
  end

  protected

  # Returns the Encryption Configuration
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
    config = YAML.load_file(filename || File.join(Rails.root, "config", "symmetric-encryption.yml"))[environment || Rails.env]

    # Default cipher
    default_cipher = config['cipher'] || 'aes-256-cbc'
    cfg = {}

    # Hard coded symmetric_key? - Dev / Testing use only!
    if symmetric_key = (config['key'] || config['symmetric_key'])
      raise "SymmetricEncryption Cannot hard code Production encryption keys in #{filename}" if (environment || Rails.env) == 'production'
      cfg[:key]     = symmetric_key
      cfg[:iv]      = config['iv'] || config['symmetric_iv']
      cfg[:cipher]  = default_cipher

    elsif ciphers = config['ciphers']
      raise "Missing mandatory config parameter 'private_rsa_key'" unless cfg[:private_rsa_key] = config['private_rsa_key']

      cfg[:ciphers] = ciphers.collect do |cipher_cfg|
        key_filename = cipher_cfg['key_filename'] || cipher_cfg['symmetric_key_filename']
        raise "Missing mandatory 'key_filename' for environment:#{environment} in #{filename}" unless key_filename
        iv_filename = cipher_cfg['iv_filename'] || cipher_cfg['symmetric_iv_filename']
        {
          :cipher       => cipher_cfg['cipher'] || default_cipher,
          :key_filename => key_filename,
          :iv_filename  => iv_filename,
          :encoding     => cipher_cfg['encoding'],
          :version      => cipher_cfg['version']
        }
      end

    else
      # Migrate old format config
      raise "Missing mandatory config parameter 'private_rsa_key'" unless cfg[:private_rsa_key] = config['private_rsa_key']
      cfg[:ciphers] = [ {
          :cipher       => default_cipher,
          :key_filename => config['symmetric_key_filename'],
          :iv_filename  => config['symmetric_iv_filename'],
        } ]
    end

    cfg
  end

  # Returns an instance of SymmetricEncryption::Cipher initialized from keys
  # stored in files
  #
  # Raises an Exception on failure
  #
  # Parameters:
  #   cipher
  #     Encryption cipher for the symmetric encryption key
  #   private_key
  #     Key used to unlock file containing the actual symmetric key
  #   key_filename
  #     Name of file containing symmetric key encrypted using the public
  #     key matching the supplied private_key
  #   iv_filename
  #     Optional. Name of file containing symmetric key initialization vector
  #     encrypted using the public key matching the supplied private_key
  def self.cipher_from_encrypted_files(private_rsa_key, cipher_conf)
    # Load Encrypted Symmetric keys
    key_filename =  cipher_conf[:key_filename]
    encrypted_key = begin
      File.read(key_filename)
    rescue Errno::ENOENT
      puts "\nSymmetric Encryption key file: '#{key_filename}' not found or readable."
      puts "To generate the keys for the first time run: rails generate symmetric_encryption:new_keys\n\n"
      return
    end

    iv_filename =  cipher_conf[:iv_filename]
    encrypted_iv = begin
      File.read(iv_filename) if iv_filename
    rescue Errno::ENOENT
      puts "\nSymmetric Encryption initialization vector file: '#{iv_filename}' not found or readable."
      puts "To generate the keys for the first time run: rails generate symmetric_encryption:new_keys\n\n"
      return
    end

    # Decrypt Symmetric Keys
    rsa = OpenSSL::PKey::RSA.new(private_rsa_key)
    iv = rsa.private_decrypt(encrypted_iv) if iv_filename
    Cipher.new(
      :key      => rsa.private_decrypt(encrypted_key),
      :iv       => iv,
      :cipher   => cipher_conf[:cipher],
      :encoding => cipher_conf[:encoding],
      :version  => cipher_conf[:version]
    )
  end

  # With Ruby 1.9 strings have encodings
  if defined?(Encoding)
    BINARY_ENCODING = Encoding.find("binary")
    UTF8_ENCODING = Encoding.find("UTF-8")
  end

end