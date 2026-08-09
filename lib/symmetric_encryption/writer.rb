require "openssl"

module SymmetricEncryption
  # Write to encrypted files and other IO streams.
  #
  # Features:
  # * Encryption on the fly whilst writing files.
  # * Large file support by only buffering small amounts of data in memory.
  # * Underlying buffering to ensure that encrypted data fits
  #   into the Symmetric Encryption Cipher block size.
  #   Only the last block in the file will be padded if it is less than the block size.
  class Writer
    # Target file name extensions that hold already compressed data, so that compressing them
    # again only costs time. `xls\w` covers the modern Excel formats, which are zip containers.
    # The original `.xls` is deliberately not included, it is not compressed.
    ALREADY_COMPRESSED = /\.(zip|gz|gzip|xls\w)\z/i

    # Open a file for writing, or use the supplied IO Stream.
    #
    # Parameters:
    #   file_name_or_stream: [String|IO]
    #     The file_name to open if a string, otherwise the stream to use.
    #     The file or stream will be closed on completion, use .initialize to
    #     avoid having the stream closed automatically.
    #
    #   compress: [true|false]
    #     Uses Zlib to compress the data before it is encrypted and
    #     written to the file/stream.
    #     Default: true, unless the file_name extension indicates it is already compressed.
    #
    # Note: Compression occurs before encryption
    #
    # # Example: Encrypt and write data to a file
    # SymmetricEncryption::Writer.open('test_file.enc') do |file|
    #   file.write "Hello World\n"
    #   file.write 'Keep this secret'
    # end
    #
    # # Example: Compress, Encrypt and write data to a file
    # SymmetricEncryption::Writer.open('encrypted_compressed.enc', compress: true) do |file|
    #   file.write "Hello World\n"
    #   file.write "Compress this\n"
    #   file.write "Keep this safe and secure\n"
    # end
    #
    # # Example: Writing to a CSV file
    #  require 'csv'
    #  begin
    #    # Must supply :row_sep for CSV otherwise it will attempt to read from and then rewind the file
    #    csv = CSV.new(SymmetricEncryption::Writer.open('csv.enc'), row_sep: "\n")
    #    csv << [1,2,3,4,5]
    #  ensure
    #    csv.close if csv
    #  end
    def self.open(file_name_or_stream, compress: nil, **args)
      if file_name_or_stream.is_a?(String)
        # Test the extension before the name is replaced by the open file below.
        compress = !file_name_or_stream.match?(ALREADY_COMPRESSED) if compress.nil?
        # Not the block form: without a block this method returns the writer, and closing the
        # underlying file is then the caller's job. The ensure below covers the block form.
        file_name_or_stream = ::File.open(file_name_or_stream, "wb") # rubocop:disable Style/FileOpen
      elsif compress.nil?
        compress = true
      end

      begin
        file = new(file_name_or_stream, compress: compress, **args)
        file = Zlib::GzipWriter.new(file) if compress
        block_given? ? yield(file) : file
      ensure
        file.close if block_given? && file.respond_to?(:closed?) && !file.closed?
      end
    end

    # Write the contents of a string in memory to an encrypted file / stream.
    #
    # Notes:
    # * Do not use this method for writing large files.
    def self.write(file_name_or_stream, data, **args)
      Writer.open(file_name_or_stream, **args) { |f| f.write(data) }
    end

    # Encrypt an entire file.
    #
    # Returns [Integer] the number of encrypted bytes written to the target file.
    #
    # Params:
    #   source: [String|IO]
    #     Source file_name or IOStream
    #
    #   target: [String|IO]
    #     Target file_name or IOStream
    #
    #   compress: [true|false]
    #     Whether to compress the target file prior to encryption.
    #     Default: true, unless `target` is a file name whose extension indicates that it is
    #     already compressed. See `.open`.
    #
    # Notes:
    # * The file contents are streamed so that the entire file is _not_ loaded into memory.
    def self.encrypt(source:, target:, **args)
      Writer.open(target, **args) { |output_file| IO.copy_stream(source, output_file) }
    end

    # Encrypt data before writing to the supplied stream
    # Marginally over the complexity limit: the branches validate the combinations of
    # random_key, random_iv and cipher_name against each other before any data is written.
    # rubocop:disable Metrics/CyclomaticComplexity
    def initialize(ios, version: nil, cipher_name: nil, header: true, random_key: true, random_iv: true,
                   compress: false, chunk_size: Header::DEFAULT_CHUNK_SIZE)
      # rubocop:enable Metrics/CyclomaticComplexity
      # Compress is only used at this point for setting the flag in the header
      @ios = ios
      raise(ArgumentError, "When :random_key is true, :random_iv must also be true") if random_key && !random_iv
      if cipher_name && !random_key && !random_iv
        raise(ArgumentError, "Cannot supply a :cipher_name unless both :random_key and :random_iv are true")
      end

      # Cipher to encrypt the random_key, or the entire file.
      # Raises when there is no cipher with this version.
      cipher = SymmetricEncryption.cipher(version)

      @size          = 0
      @closed        = false
      @authenticated = ::OpenSSL::Cipher.new(cipher_name || cipher.cipher_name).authenticated?
      if @authenticated
        initialize_authenticated(
          cipher, cipher_name: cipher_name, compress: compress, random_key: random_key,
                  random_iv: random_iv, chunk_size: chunk_size
        )
        return
      end

      # Force header if compressed or using random iv, key
      if (header == true) || compress || random_key || random_iv
        header = Header.new(version: cipher.version, compress: compress, cipher_name: cipher_name)
      end

      @stream_cipher = ::OpenSSL::Cipher.new(cipher_name || cipher.cipher_name)
      @stream_cipher.encrypt

      if random_key
        header.key = @stream_cipher.key = @stream_cipher.random_key
      else
        @stream_cipher.key = cipher.send(:key)
      end

      if random_iv
        header.iv = @stream_cipher.iv = @stream_cipher.random_iv
      elsif cipher.iv
        @stream_cipher.iv = cipher.iv
      end

      @ios.write(header.to_s) if header
    end

    # Close the IO Stream.
    #
    # Notes:
    # * Flushes any unwritten data.
    # * Once an EncryptionWriter has been closed a new instance must be
    #   created before writing again.
    # * Closes the passed in io stream or file.
    # * `close` must be called _before_ the supplied stream is closed.
    #
    # It is recommended to call Symmetric::EncryptedStream.open
    # rather than creating an instance of Symmetric::Writer directly to
    # ensure that the encrypted stream is closed before the stream itself is closed.
    # Positional to match IO#close. Changing it to a keyword would break existing callers.
    def close(close_child_stream = true) # rubocop:disable Style/OptionalBooleanParameter
      return if closed?

      if @authenticated
        close_authenticated
      elsif size.positive?
        final = @stream_cipher.final
        @ios.write(final) unless final.empty?
      end
      @ios.close if close_child_stream
      @closed = true
    end

    # Write to the IO Stream as encrypted data.
    #
    # Returns [Integer] the number of bytes written.
    if defined?(JRuby)
      def write(data)
        return unless data
        return authenticated_write(data) if @authenticated

        bytes = data.to_s
        @size += bytes.size
        partial = @stream_cipher.update(bytes)
        @ios.write(partial) unless partial.empty?
        bytes.size
      end
    else
      def write(data)
        return unless data
        return authenticated_write(data) if @authenticated

        bytes = data.to_s
        @size += bytes.size
        partial = @stream_cipher.update(bytes, @cipher_buffer ||= "".b)
        @ios.write(partial) unless partial.empty?
        bytes.size
      end
    end

    # Write to the IO Stream as encrypted data.
    #
    # Returns [SymmetricEncryption::Writer] self
    #
    # Example:
    #   file << "Hello.\n" << 'This is Jack'
    def <<(data)
      write(data)
      self
    end

    # Flush the output stream.
    # Does not flush internal buffers since encryption requires all data to
    # be written following the encryption block size.
    #  Needed by XLS gem.
    def flush
      @ios.flush
    end

    # Returns [true|false] whether this stream is closed.
    def closed?
      @closed || (@ios.respond_to?(:closed?) && @ios.closed?)
    end

    # Returns [Integer] the number of unencrypted and uncompressed bytes
    # written to the file so far.
    attr_reader :size

    private

    # Prepares to write with an authenticated cipher, such as `aes-256-gcm`.
    #
    # Nothing is written yet, not even the header. Where the auth tag goes depends on how much
    # data there turns out to be, and that is not known until either the stream ends or it
    # overflows the first chunk:
    #
    # * Up to one chunk of data is written as a single encrypted value, with its auth tag in the
    #   header, exactly as `Cipher#encrypt` writes one. No chunk overhead at all.
    # * More than that is written as a chunked stream, and the header says so. See
    #   `SymmetricEncryption::ChunkedStream`.
    def initialize_authenticated(cipher, cipher_name:, compress:, random_key:, random_iv:, chunk_size:)
      unless random_iv
        raise(
          ArgumentError,
          "An authenticated cipher needs a new iv for every stream, so :random_iv cannot be false. Re-using one " \
          "iv across streams encrypted with the same key exposes the data and makes the auth tag forgeable."
        )
      end

      @cipher = cipher
      @stream_cipher_name = cipher_name || cipher.cipher_name
      @compress          = compress
      @chunk_size        = chunk_size
      @stream_key        = random_key ? ::OpenSSL::Cipher.new(@stream_cipher_name).random_key : cipher.send(:key)
      @random_key        = random_key
      @buffer            = "".b
      @chunk_number      = 0
      @chunked_stream    = nil
    end

    # Buffers the data, and starts a chunked stream once there is more of it than one chunk holds.
    def authenticated_write(data)
      bytes = data.to_s
      @size += bytes.bytesize
      @buffer << bytes.b

      # Only once there is more than a chunk of data is it known that the chunk being written is
      # not the last one, which is part of what each chunk is authenticated against.
      write_chunk(last: false) while @buffer.bytesize > @chunk_size

      bytes.bytesize
    end

    # Writes out whatever is left, in whichever of the two formats fits.
    def close_authenticated
      return close_unchunked if @chunked_stream.nil?

      write_chunk(last: true)
    end

    # Writes the stream as a single encrypted value with its auth tag in the header, for data that
    # fits in one chunk.
    def close_unchunked
      header = Header.new(
        version:       @cipher.version,
        compress:      @compress,
        cipher_name:   @stream_cipher_name == @cipher.cipher_name ? nil : @stream_cipher_name,
        key:           (@stream_key if @random_key),
        authenticated: true
      )

      openssl_cipher = ::OpenSSL::Cipher.new(@stream_cipher_name)
      openssl_cipher.encrypt
      openssl_cipher.key = @stream_key
      header.iv          = openssl_cipher.iv = openssl_cipher.random_iv
      # `auth_data` is memoized for an authenticated header, so these are the same bytes that
      # `to_s` writes out below, including the encrypted key.
      openssl_cipher.auth_data = header.auth_data

      encrypted = openssl_cipher.update(@buffer)
      encrypted << openssl_cipher.final
      header.auth_tag = openssl_cipher.auth_tag(Header::AUTH_TAG_SIZE)

      @ios.write(header.to_s)
      @ios.write(encrypted) unless encrypted.empty?
    end

    # Writes one chunk, starting the chunked stream if this is the first.
    def write_chunk(last:)
      start_chunked_stream if @chunked_stream.nil?

      data = last ? @buffer : @buffer.byteslice(0, @chunk_size)
      @ios.write(@chunked_stream.encrypt(@chunk_number, data, last: last))
      @chunk_number += 1
      @buffer = last ? "".b : @buffer.byteslice(@chunk_size..) || "".b
    end

    # Writes the header of a chunked stream, and prepares to encrypt its chunks.
    def start_chunked_stream
      nonce_prefix = ChunkedStream.generate_nonce_prefix
      header       = Header.new(
        version:     @cipher.version,
        compress:    @compress,
        cipher_name: @stream_cipher_name == @cipher.cipher_name ? nil : @stream_cipher_name,
        key:         (@stream_key if @random_key),
        iv:          nonce_prefix,
        chunk_size:  @chunk_size
      )

      # Serialized exactly once. A header holding a key is not deterministic, the key is encrypted
      # again with a new random iv on every call, and every chunk is authenticated against the
      # bytes that were actually written.
      header_bytes = header.to_s
      @ios.write(header_bytes)

      @chunked_stream = ChunkedStream.new(
        cipher_name:  @stream_cipher_name,
        key:          @stream_key,
        nonce_prefix: nonce_prefix,
        header_bytes: header_bytes,
        chunk_size:   @chunk_size
      )
    end
  end
end
