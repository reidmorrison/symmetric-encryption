require "openssl"

module SymmetricEncryption
  # Encrypts and decrypts a stream one chunk at a time with an authenticated cipher, so that a
  # file can be authenticated as it is read instead of only once all of it has been read.
  #
  # An authenticated cipher applied to a whole stream produces a single auth tag, which only
  # exists once everything has been encrypted and can only be checked once everything has been
  # decrypted. A reader would therefore have to hand out data long before it could know whether
  # that data had been tampered with. Splitting the stream into chunks, each with its own auth
  # tag, means every chunk is verified before any of it is returned.
  #
  # On disk a chunk is its encrypted data followed by its auth tag. Nothing else. Everything the
  # reader needs in order to decrypt a chunk is derived rather than stored, because a value that
  # is stored is a value an attacker can change:
  #
  # * The nonce is `prefix || chunk number || last chunk`, where the 7 byte prefix is generated
  #   once per stream and held in the stream's header. Deriving it from the chunk's position is
  #   what stops chunks being reordered, duplicated or dropped: a chunk moved to another position
  #   is decrypted with a different nonce, and fails its auth tag check.
  # * Including whether the chunk is the last one is what stops the stream being truncated.
  #   Without it, cutting the end off a file would leave every remaining chunk verifying
  #   perfectly. With it, the chunk that ends up last was encrypted as a middle chunk, and fails.
  # * The chunk's length is the chunk size for every chunk except the last, which is shorter.
  #
  # Every chunk is also authenticated against the bytes of the stream's header, which binds the
  # chunks to the header they were written with, and so to its version, flags, chunk size and
  # encrypted key. Chunks cannot be moved from one stream to another.
  #
  # Not used for a value that fits in a single chunk. `Writer` only switches to a chunked stream
  # once there is more data than one chunk holds, and puts the auth tag in the header otherwise.
  class ChunkedStream
    # The number of bytes of the nonce that are generated once per stream, leaving 4 bytes for the
    # chunk number and 1 byte for whether the chunk is the last one.
    NONCE_PREFIX_SIZE = 7

    # The number of chunks a single stream can hold, limited by the 4 byte chunk number.
    MAX_CHUNKS = 2**32

    attr_reader :chunk_size

    # Returns [String] a new random nonce prefix, to be held in the header of a chunked stream.
    def self.generate_nonce_prefix
      ::OpenSSL::Random.random_bytes(NONCE_PREFIX_SIZE)
    end

    # Parameters:
    #   cipher_name [String]
    #     The authenticated cipher to use, for example `aes-256-gcm`.
    #
    #   key [String]
    #     The key for this stream. Generated per stream by `Writer`, and held in the stream's
    #     header encrypted with the global cipher.
    #
    #   nonce_prefix [String]
    #     The random prefix that the nonce of every chunk in this stream is derived from.
    #
    #   header_bytes [String]
    #     The bytes of the stream's header, which every chunk is authenticated against.
    #
    #   chunk_size [Integer]
    #     The number of plain text bytes in each chunk, except the last.
    def initialize(cipher_name:, key:, nonce_prefix:, header_bytes:, chunk_size: Header::DEFAULT_CHUNK_SIZE)
      unless ::OpenSSL::Cipher.new(cipher_name).authenticated?
        raise(ArgumentError, "#{cipher_name} is not an authenticated cipher, so its chunks cannot be authenticated")
      end

      if nonce_prefix.to_s.b.length != NONCE_PREFIX_SIZE
        raise(ArgumentError, "The nonce prefix must be exactly #{NONCE_PREFIX_SIZE} bytes")
      end

      @cipher_name   = cipher_name
      @key           = key
      @nonce_prefix  = nonce_prefix.b
      @header_bytes  = header_bytes.b
      @chunk_size    = chunk_size
    end

    # Returns [Integer] the number of bytes a chunk holding `chunk_size` plain text bytes occupies.
    def frame_size
      @frame_size ||= chunk_size + Header::AUTH_TAG_SIZE
    end

    # Returns [String] the encrypted chunk, its auth tag appended.
    #
    # Parameters:
    #   number [Integer] which chunk this is, counting from zero.
    #   data [String] the plain text, `chunk_size` bytes unless this is the last chunk.
    #   last [true|false] whether this is the last chunk in the stream.
    def encrypt(number, data, last:)
      openssl_cipher = cipher_for(number, last: last, direction: :encrypt)

      encrypted = openssl_cipher.update(data)
      encrypted << openssl_cipher.final
      encrypted << openssl_cipher.auth_tag(Header::AUTH_TAG_SIZE)
    end

    # Returns [String] the decrypted chunk.
    #
    # Raises OpenSSL::Cipher::CipherError when the chunk has been changed, moved to another
    # position in the stream, moved to another stream, or when the stream has been truncated so
    # that a chunk that was not the last one now is.
    #
    # Parameters:
    #   number [Integer] which chunk this is, counting from zero.
    #   frame [String] the encrypted chunk with its auth tag appended.
    #   last [true|false] whether this is the last chunk in the stream.
    def decrypt(number, frame, last:)
      if frame.bytesize < Header::AUTH_TAG_SIZE
        raise(
          SymmetricEncryption::CipherError,
          "Chunk #{number} is #{frame.bytesize} bytes, too short to hold its #{Header::AUTH_TAG_SIZE} byte auth tag. " \
          "The stream has been truncated."
        )
      end

      data           = frame.byteslice(0, frame.bytesize - Header::AUTH_TAG_SIZE)
      openssl_cipher = cipher_for(number, last: last, direction: :decrypt)
      openssl_cipher.auth_tag = frame.byteslice(frame.bytesize - Header::AUTH_TAG_SIZE, Header::AUTH_TAG_SIZE)

      decrypted = openssl_cipher.update(data)
      decrypted << openssl_cipher.final
    end

    # Reads a chunked stream from an IO stream, one chunk at a time.
    #
    # Holds the read ahead buffer and the number of the next chunk. `Reader` keeps one of these
    # rather than the three separate pieces of state, so that reading an unauthenticated stream,
    # which has none of them, is not slowed down by the extra instance variables that would
    # otherwise be on every reader.
    class Buffer
      def initialize(stream, ios, buffer_size:)
        @stream       = stream
        @ios          = ios
        @buffer_size  = [buffer_size, stream.frame_size].max
        @buffer       = "".b
        @chunk_number = 0
      end

      # Adds bytes that have already been read out of the stream, after the header.
      def <<(bytes)
        @buffer << bytes if bytes
        self
      end

      # Returns [true|false] whether every byte read so far has been decrypted.
      def empty?
        @buffer.empty?
      end

      # Returns [String] the next decrypted chunk, or nil once the stream is exhausted.
      #
      # Whether a chunk is the last one is part of what it is authenticated against, so this
      # always reads one byte further than the chunk it is about to decrypt.
      def next_chunk
        frame_size = @stream.frame_size
        @buffer << @ios.read(@buffer_size, @read_buffer ||= "".b).to_s while (@buffer.bytesize <= frame_size) && !@ios.eof?
        return if @buffer.empty?

        last  = @buffer.bytesize <= frame_size
        frame = @buffer.slice!(0, last ? @buffer.bytesize : frame_size)

        decrypted      = @stream.decrypt(@chunk_number, frame, last: last)
        @chunk_number += 1
        decrypted
      end
    end

    private

    attr_reader :cipher_name, :key, :nonce_prefix, :header_bytes

    # Returns [OpenSSL::Cipher] ready to encrypt or decrypt the chunk numbered `number`.
    #
    # A new cipher for every chunk, so that a stream can be read or written by more than one
    # thread, and so that seeking to a chunk needs no state from the chunks before it.
    def cipher_for(number, last:, direction:)
      if number >= MAX_CHUNKS
        raise(
          SymmetricEncryption::CipherError,
          "A chunked stream holds at most #{MAX_CHUNKS} chunks of #{chunk_size} bytes"
        )
      end

      openssl_cipher = ::OpenSSL::Cipher.new(cipher_name)
      openssl_cipher.public_send(direction)
      openssl_cipher.key = key
      openssl_cipher.iv  = nonce_for(number, last: last)
      # Binds the chunk to the header of the stream it belongs to.
      openssl_cipher.auth_data = header_bytes
      openssl_cipher
    end

    # Returns [String] the 12 byte nonce for the chunk numbered `number`.
    def nonce_for(number, last:)
      "#{nonce_prefix}#{[number].pack('N')}#{last ? 1.chr : 0.chr}".b
    end
  end
end
