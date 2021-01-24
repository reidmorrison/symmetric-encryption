module SymmetricEncryption
  # Defines the Header Structure returned when parsing the header.
  #
  # Note:
  # * Header only works against binary encrypted data that has not been decoded.
  # * Decode data first before trying to extract its header.
  # * Decoding is not required when encoding is set to `:none`.
  class Header
    # Encrypted data includes this header prior to encoding when
    # `always_add_header` is true.
    MAGIC_HEADER      = "@EnC".force_encoding(SymmetricEncryption::BINARY_ENCODING)
    MAGIC_HEADER_SIZE = MAGIC_HEADER.size

    # [true|false] Whether to compress the data before encryption.
    # If supplied in the header.
    attr_accessor :compress

    # [String] IV used to encrypt the data.
    # If supplied in the header.
    attr_accessor :iv

    # [String] Key used to encrypt the data.
    # If supplied in the header.
    attr_accessor :key

    # [String] Name of the cipher used.
    attr_accessor :cipher_name

    # [Integer] Version of the cipher used.
    attr_reader :version

    # [String] Binary auth tag used to encrypt the data.
    # Usually 16 bytes.
    # Present when using an authenticated encryption mode.
    attr_reader :auth_tag

    # Returns whether the supplied buffer starts with a symmetric_encryption header
    # Note: The encoding of the supplied buffer is forced to binary if not already binary
    def self.present?(buffer)
      return false if buffer.nil? || (buffer == "")

      buffer.force_encoding(SymmetricEncryption::BINARY_ENCODING)
      buffer.start_with?(MAGIC_HEADER)
    end

    # Returns a magic header for this cipher instance that can be placed at
    # the beginning of a file or stream to indicate how the data was encrypted
    #
    # Parameters
    #   compress [true|false]
    #     Whether the data should be compressed before encryption.
    #     Default: false
    #
    #   iv [String]
    #     The iv to to put in the header
    #     Default: nil : Exclude from header
    #
    #   key [String]
    #     The key to to put in the header.
    #     The key is encrypted using the global encryption key
    #     Default: nil : Exclude key from header
    #
    #   version: [Integer (0..255)]
    #     Version of the global cipher used to encrypt the data,
    #     or the encryption key if supplied.
    #     default: The current global encryption cipher version.
    #
    #   cipher_name [String]
    #     The cipher_name to be used for encrypting the data portion.
    #     For example 'aes-256-cbc'
    #     `key` if supplied is encrypted with the cipher name based on the cipher version in this header.
    #     Intended for use when encrypting large files with a different cipher to the global one.
    #     Default: nil : Exclude cipher_name name from header
    def initialize(version: SymmetricEncryption.cipher.version,
                   compress: false,
                   iv: nil,
                   key: nil,
                   cipher_name: nil,
                   auth_tag: nil)

      @version     = version
      @compress    = compress
      @iv          = iv
      @key         = key
      @cipher_name = cipher_name
      @auth_tag    = auth_tag
    end

    # Returns [SymmetricEncryption::Cipher] the cipher used to decrypt or encrypt the key
    # specified in this header, if supplied.
    def cipher
      @cipher ||= SymmetricEncryption.cipher(version)
    end

    def version=(version)
      @version = version
      @cipher  = nil
    end

    def compressed?
      @compress
    end

    # Returns [String] the encrypted data without header
    # Returns nil if no header is present
    #
    # The supplied buffer will be updated directly and
    # its header will be stripped if present.
    #
    # Parameters
    #   buffer
    #     String to extract the header from
    def parse!(buffer)
      offset = parse(buffer)
      return if offset.zero?

      buffer.slice!(0..offset - 1)
      buffer
    end

    # Returns [Integer] the offset within the buffer of the data after the header has been read.
    #
    # Returns 0 if no header is present
    def parse(buffer, offset = 0)
      return 0 if buffer.nil? || (buffer == "") || (buffer.length <= MAGIC_HEADER_SIZE + 2)

      # Symmetric Encryption Header
      #
      # Consists of:
      #    4 Bytes: Magic Header Prefix: @Enc
      #    1 Byte:  The version of the cipher used to encrypt the header.
      #    1 Byte:  Flags:
      #       Bit 1: Whether the data is compressed
      #       Bit 2: Whether the IV is included
      #       Bit 3: Whether the Key is included
      #       Bit 4: Whether the Cipher Name is included
      #       Bit 5: Future use
      #       Bit 6: Future use
      #       Bit 7: Future use
      #       Bit 8: Future use
      #    2 Bytes: IV Length (little endian), if included.
      #      IV in binary form.
      #    2 Bytes: Key Length (little endian), if included.
      #      Key in binary form
      #    2 Bytes: Cipher Name Length (little endian), if included.
      #      Cipher name it UTF8 text

      buffer.force_encoding(SymmetricEncryption::BINARY_ENCODING)
      header = buffer.byteslice(offset, MAGIC_HEADER_SIZE)
      return 0 unless header == MAGIC_HEADER

      offset += MAGIC_HEADER_SIZE

      # Remove header and extract flags
      self.version = buffer.getbyte(offset)
      offset += 1

      unless cipher
        raise(
          SymmetricEncryption::CipherError,
          "Cipher with version:#{version.inspect} not found in any of the configured SymmetricEncryption ciphers"
        )
      end

      flags = buffer.getbyte(offset)
      offset += 1

      self.compress = (flags & FLAG_COMPRESSED) != 0

      if (flags & FLAG_IV).zero?
        self.iv = nil
      else
        self.iv, offset = read_string(buffer, offset)
      end

      if (flags & FLAG_KEY).zero?
        self.key = nil
      else
        encrypted_key, offset = read_string(buffer, offset)
        self.key              = cipher.binary_decrypt(encrypted_key)
      end

      if (flags & FLAG_CIPHER_NAME).zero?
        self.cipher_name = nil
      else
        self.cipher_name, offset = read_string(buffer, offset)
      end

      if (flags & FLAG_AUTH_TAG).zero?
        self.auth_tag = nil
      else
        self.auth_tag, offset = read_string(buffer, offset)
      end

      offset
    end

    # Returns [String] this header as a string
    def to_s
      flags = 0
      flags |= FLAG_COMPRESSED if compressed?
      flags |= FLAG_IV if iv
      flags |= FLAG_KEY if key
      flags |= FLAG_CIPHER_NAME if cipher_name
      flags |= FLAG_AUTH_TAG if auth_tag

      header = "#{MAGIC_HEADER}#{version.chr(SymmetricEncryption::BINARY_ENCODING)}#{flags.chr(SymmetricEncryption::BINARY_ENCODING)}"

      if iv
        header << [iv.length].pack("v")
        header << iv
      end

      if key
        encrypted = cipher.binary_encrypt(key, header: false)
        header << [encrypted.length].pack("v")
        header << encrypted
      end

      if cipher_name
        header << [cipher_name.length].pack("v")
        header << cipher_name
      end

      if auth_tag
        header << [auth_tag.length].pack("v")
        header << auth_tag
      end

      header
    end

    private

    FLAG_COMPRESSED  = 0b1000_0000
    FLAG_IV          = 0b0100_0000
    FLAG_KEY         = 0b0010_0000
    FLAG_CIPHER_NAME = 0b0001_0000
    FLAG_AUTH_TAG    = 0b0000_1000

    attr_writer :auth_tag

    # Extracts a string from the supplied buffer.
    # The buffer starts with a 2 byte length indicator in little endian format.
    #
    # Parameters
    #   buffer [String]
    #   offset [Integer]
    #     Start position within the buffer.
    #
    # Returns [string, offset]
    #   string [String]
    #     The string copied from the buffer.
    #   offset [Integer]
    #     The new offset within the buffer.
    def read_string(buffer, offset)
      # TODO: Length check
      #   Exception when
      #   - offset exceeds length of buffer
      #   byteslice truncates when too long, but returns nil when start is beyond end of buffer
      len = buffer.byteslice(offset, 2).unpack("v").first
      offset += 2
      out = buffer.byteslice(offset, len)
      [out, offset + len]
    end
  end
end
