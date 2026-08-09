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
    MAGIC_HEADER      = "@EnC".b.freeze
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
    # Always 16 bytes, see `AUTH_TAG_SIZE`.
    # Present when using an authenticated encryption mode.
    attr_reader :auth_tag

    # The number of bytes in the auth tag of an authenticated cipher.
    #
    # GCM accepts a shorter auth tag, and OpenSSL does not reject one, so an attacker who can
    # write to the encrypted value could truncate the tag to a single byte and then forge it in
    # at most 256 attempts. See https://github.com/ruby/openssl/issues/63. The length is fixed
    # here, and checked on the way in, so that a truncated tag is rejected rather than trusted.
    AUTH_TAG_SIZE = 16

    # [Integer] The number of plain text bytes in each chunk of a chunked stream.
    # Only present when `chunked?`. See `SymmetricEncryption::ChunkedStream`.
    attr_reader :chunk_size

    # The chunk sizes that are accepted, as powers of two: 1 KB to 16 MB.
    #
    # Bounded because the chunk size is read out of the header before anything has been
    # authenticated, and it decides how large a buffer the reader allocates for each chunk.
    MIN_CHUNK_SIZE_EXPONENT = 10
    MAX_CHUNK_SIZE_EXPONENT = 24

    # The chunk size used unless another one is asked for.
    DEFAULT_CHUNK_SIZE = 64 * 1024

    # Returns whether the supplied buffer starts with a symmetric_encryption header
    # The supplied buffer is not modified, and may be frozen.
    def self.present?(buffer)
      return false if buffer.nil? || (buffer == "")

      # Compare bytes, so that the result does not depend on the encoding of the buffer.
      buffer.byteslice(0, MAGIC_HEADER_SIZE)&.b == MAGIC_HEADER
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
    #   auth_tag [String]
    #     The auth tag produced by an authenticated cipher, such as `aes-256-gcm`.
    #     Default: nil : Exclude the auth tag from the header
    #
    #   authenticated [true|false]
    #     Whether the data is encrypted with an authenticated cipher, and therefore whether the
    #     header will carry an auth tag. Only needed while encrypting, when the auth tag is not
    #     known yet: an authenticated cipher needs its additional authenticated data before it
    #     can produce the tag. See `#auth_data`.
    #     Default: whether `auth_tag` was supplied.
    #   chunk_size [Integer]
    #     The number of plain text bytes in each chunk, when the data is written as a chunked
    #     stream. Each chunk carries its own auth tag, so that a stream can be authenticated as
    #     it is read instead of only once all of it has been read.
    #     Default: nil : Not a chunked stream
    def initialize(version: SymmetricEncryption.cipher.version,
                   compress: false,
                   iv: nil,
                   key: nil,
                   cipher_name: nil,
                   auth_tag: nil,
                   authenticated: !auth_tag.nil?,
                   chunk_size: nil)
      @version         = version
      @compress        = compress
      @iv              = iv
      @key             = key
      @cipher_name     = cipher_name
      @authenticated   = authenticated
      self.chunk_size  = chunk_size if chunk_size
      self.auth_tag    = auth_tag if auth_tag
    end

    # Returns [true|false] whether the data is encrypted with an authenticated cipher, and
    # therefore whether this header carries an auth tag.
    def authenticated?
      @authenticated
    end

    # Returns [true|false] whether the data is a chunked stream, each chunk of which carries its
    # own auth tag. A chunked stream has no auth tag in its header.
    def chunked?
      !@chunk_size.nil?
    end

    # Returns [String] the exact bytes of this header, as they were parsed out of the stream.
    #
    # Every chunk of a chunked stream is authenticated against these bytes, which binds the chunks
    # to this header: to its version, its flags, its chunk size and its encrypted key. Only
    # captured while parsing a chunked stream, since slicing it out costs an allocation that the
    # far more common path of decrypting a single value does not need.
    attr_reader :header_bytes

    # Rejects a chunk size that is not a power of two within the supported range.
    def chunk_size=(chunk_size)
      exponent = chunk_size && Math.log2(chunk_size)
      unless exponent && (exponent % 1).zero? &&
             exponent.between?(MIN_CHUNK_SIZE_EXPONENT, MAX_CHUNK_SIZE_EXPONENT)
        raise(
          SymmetricEncryption::CipherError,
          "Chunk size #{chunk_size.inspect} is not supported. It has to be a power of two between " \
          "#{2**MIN_CHUNK_SIZE_EXPONENT} and #{2**MAX_CHUNK_SIZE_EXPONENT} bytes."
        )
      end

      @chunk_size = chunk_size
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

    # Rejects an auth tag that is not exactly `AUTH_TAG_SIZE` bytes, since OpenSSL accepts a
    # truncated one and a truncated tag is not expensive to forge.
    #
    # Held as binary, so that its length is always its length in bytes, and so that appending it
    # to the rest of the header cannot fail on an encoding mismatch.
    def auth_tag=(auth_tag)
      auth_tag = auth_tag&.to_s&.b
      if auth_tag && (auth_tag.length != AUTH_TAG_SIZE)
        raise(
          SymmetricEncryption::CipherError,
          "The auth tag must be exactly #{AUTH_TAG_SIZE} bytes, but is #{auth_tag.length} bytes. " \
          "A shorter auth tag is not accepted, because it is not expensive to forge."
        )
      end

      @auth_tag = auth_tag
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
      # `parse` returns a byte offset, so the buffer has to be binary for `slice!` below to
      # cut in the same units. Unlike `parse`, this method modifies the buffer by contract.
      buffer&.force_encoding(SymmetricEncryption::BINARY_ENCODING)

      offset = parse(buffer)
      return if offset.zero?

      buffer.slice!(0..(offset - 1))
      buffer
    end

    # Returns [Integer] the offset within the buffer of the data after the header has been read.
    #
    # Returns 0 if no header is present
    #
    # The supplied buffer is not modified, and may be frozen. Use `parse!` to strip the header
    # from the buffer itself.
    #
    # Marginally over the ABC and length limits, and deliberately left alone: this walks the
    # on-disk header format field by field, and splitting it up would obscure the byte order it
    # depends on.
    def parse(buffer, offset = 0) # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
      return 0 if buffer.nil? || (buffer == "") || (buffer.length <= MAGIC_HEADER_SIZE + 2)

      start_offset = offset

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
      #       Bit 5: Whether the Auth Tag is included
      #       Bit 6: Whether the data is a chunked stream
      #       Bit 7: Future use
      #       Bit 8: Future use
      #    2 Bytes: IV Length (little endian), if included.
      #      IV in binary form.
      #    2 Bytes: Key Length (little endian), if included.
      #      Key in binary form
      #    2 Bytes: Cipher Name Length (little endian), if included.
      #      Cipher name it UTF8 text
      #    1 Byte:  The chunk size as a power of two, if this is a chunked stream.
      #    2 Bytes: Auth Tag Length (little endian), if included.
      #      Auth tag in binary form. Always the last field, so that every byte before it can be
      #      passed to an authenticated cipher as its additional authenticated data.

      # Every read below is byte oriented, so the buffer has to be binary. Work against a
      # binary copy when it is not, rather than re-encoding the caller's string in place.
      buffer = buffer.b unless buffer.encoding == SymmetricEncryption::BINARY_ENCODING

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

      self.compress = flags.anybits?(FLAG_COMPRESSED)

      if flags.nobits?(FLAG_IV)
        self.iv = nil
      else
        self.iv, offset = read_string(buffer, offset)
      end

      if flags.nobits?(FLAG_KEY)
        self.key = nil
      else
        encrypted_key, offset = read_string(buffer, offset)
        self.key              = cipher.binary_decrypt(encrypted_key)
      end

      if flags.nobits?(FLAG_CIPHER_NAME)
        self.cipher_name = nil
      else
        self.cipher_name, offset = read_string(buffer, offset)
      end

      if flags.nobits?(FLAG_CHUNKED)
        @chunk_size = nil
      else
        self.chunk_size = 2**buffer.getbyte(offset)
        offset += 1
      end

      if flags.nobits?(FLAG_AUTH_TAG)
        @authenticated = false
        @auth_tag      = nil
        @auth_data     = nil
      else
        @authenticated = true
        # Every byte before the auth tag is the additional authenticated data. Sliced out of the
        # buffer rather than rebuilt, so that it is exactly what the cipher was given, whether or
        # not this header is later written out again.
        @auth_data     = buffer.byteslice(start_offset, offset - start_offset)
        tag, offset    = read_string(buffer, offset)
        self.auth_tag  = tag
      end

      # Only for a chunked stream, whose chunks are each authenticated against these bytes. Every
      # other value pays nothing for it, since slicing it out costs an allocation.
      @header_bytes = buffer.byteslice(start_offset, offset - start_offset) if chunked?

      offset
    end

    # Returns [String] this header as a string
    def to_s
      return auth_data unless authenticated?

      unless auth_tag
        raise(
          SymmetricEncryption::CipherError,
          "The auth tag has to be set before an authenticated header can be written out. " \
          "It is only known once the data has been encrypted."
        )
      end

      # Not `<<`, which would append to the memoized auth data.
      "#{auth_data}#{[auth_tag.length].pack('v')}#{auth_tag}"
    end

    # Returns [String] the header bytes that precede the auth tag.
    #
    # For an authenticated cipher these bytes are the additional authenticated data (AAD). They
    # are covered by the auth tag, so that the version, the flags, the iv and the cipher name
    # cannot be changed without the tag check failing. The tag itself is excluded, since it is
    # the output of the very operation that this data is fed into.
    #
    # Memoized for an authenticated header only, so that the bytes handed to the cipher as the
    # AAD are byte for byte the bytes that `#to_s` writes out afterwards. An encrypted key in the
    # header is not deterministic, it is encrypted again with a new random iv on every call.
    def auth_data
      return build_auth_data unless authenticated?

      @auth_data ||= build_auth_data
    end

    private

    FLAG_COMPRESSED  = 0b1000_0000
    FLAG_IV          = 0b0100_0000
    FLAG_KEY         = 0b0010_0000
    FLAG_CIPHER_NAME = 0b0001_0000
    FLAG_AUTH_TAG    = 0b0000_1000
    FLAG_CHUNKED     = 0b0000_0100
    private_constant :FLAG_COMPRESSED, :FLAG_IV, :FLAG_KEY, :FLAG_CIPHER_NAME, :FLAG_AUTH_TAG,
                     :FLAG_CHUNKED

    # Returns [String] the header, excluding the auth tag. See `#auth_data`.
    def build_auth_data
      flags = 0
      flags |= FLAG_COMPRESSED if compressed?
      flags |= FLAG_IV if iv
      flags |= FLAG_KEY if key
      flags |= FLAG_CIPHER_NAME if cipher_name
      flags |= FLAG_AUTH_TAG if authenticated?
      flags |= FLAG_CHUNKED if chunked?

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

      header << Math.log2(chunk_size).to_i.chr(SymmetricEncryption::BINARY_ENCODING) if chunked?

      header
    end

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
      len = buffer.byteslice(offset, 2).unpack1("v")
      offset += 2
      out = buffer.byteslice(offset, len)
      [out, offset + len]
    end
  end
end
