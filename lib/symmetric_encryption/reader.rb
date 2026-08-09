require "openssl"

module SymmetricEncryption
  # Read from encrypted files and other IO streams
  #
  # Features:
  # * Decryption on the fly whilst reading files
  # * Large file support by only buffering small amounts of data in memory
  class Reader
    # Open a file for reading, or use the supplied IO Stream
    #
    # Parameters:
    #   file_name_or_stream:
    #     The file_name to open if a string, otherwise the stream to use
    #     The file or stream will be closed on completion, use .initialize to
    #     avoid having the stream closed automatically
    #
    #   buffer_size:
    #     Amount of data to read at a time.
    #     Minimum Value 128
    #     Default: 16384
    #
    # Note: Decryption occurs before decompression
    #
    # # Example: Read and decrypt a line at a time from a file
    # SymmetricEncryption::Reader.open('test_file') do |file|
    #   file.each_line {|line| p line }
    # end
    #
    # # Example: Read and decrypt entire file in memory
    # # Not recommended for large files
    # SymmetricEncryption::Reader.open('test_file') {|f| f.read }
    #
    # # Example: Reading a limited number of bytes at a time from the file
    # SymmetricEncryption::Reader.open('test_file') do |file|
    #   file.read(1)
    #   file.read(5)
    #   file.read
    # end
    #
    # # Example: Read and decrypt 5 bytes at a time until the end of file is reached
    # SymmetricEncryption::Reader.open('test_file') do |file|
    #   while !file.eof? do
    #     file.read(5)
    #   end
    # end
    #
    # # Example: Read, Unencrypt and decompress data in a file
    # SymmetricEncryption::Reader.open('encrypted_compressed.zip', compress: true) do |file|
    #   file.each_line {|line| p line }
    # end
    #
    # # Example: Reading from a CSV file
    #
    # require 'csv'
    # begin
    #   csv = CSV.new(SymmetricEncryption::Reader.open('csv_encrypted'))
    #   csv.each {|row| p row}
    # ensure
    #   csv.close if csv
    # end
    def self.open(file_name_or_stream, buffer_size: 16_384, **args, &block)
      ios = file_name_or_stream.is_a?(String) ? ::File.open(file_name_or_stream, "rb") : file_name_or_stream

      begin
        file = new(ios, buffer_size: buffer_size, **args)
        file = Zlib::GzipReader.new(file) if !file.eof? && file.compressed?
        block ? block.call(file) : file
      ensure
        file.close if block && file.respond_to?(:closed?) && !file.closed?
      end
    end

    # Read the entire contents of a file or stream into memory.
    #
    # Notes:
    # * Do not use this method for reading large files.
    def self.read(file_name_or_stream, **args)
      Reader.open(file_name_or_stream, **args, &:read)
    end

    # Decrypt an entire file.
    #
    # Returns [Integer] the number of unencrypted bytes written to the target file.
    #
    # Params:
    #   source: [String|IO]
    #     Source file_name or IOStream
    #
    #   target: [String|IO]
    #     Target file_name or IOStream
    #
    # Notes:
    # * The file contents are streamed so that the entire file is _not_ loaded into memory.
    def self.decrypt(source:, target:, **args)
      Reader.open(source, **args) { |input_file| IO.copy_stream(input_file, target) }
    end

    # Returns [true|false] whether the file or stream contains any data
    # excluding the header should it have one
    def self.empty?(file_name_or_stream)
      Reader.open(file_name_or_stream, &:eof?)
    end

    # Returns [true|false] whether the file contains the encryption header
    def self.header_present?(file_name)
      ::File.open(file_name, "rb") { |file| new(file).header_present? }
    end

    # After opening a file Returns [true|false] whether the file being
    # read has an encryption header
    def header_present?
      @header_present
    end

    # Decrypt data before reading from the supplied stream
    def initialize(ios, buffer_size: 4096, version: nil)
      @ios            = ios
      @buffer_size    = buffer_size
      @version          = version
      @header_present   = false
      @closed           = false
      @read_buffer      = "".b
      @encrypted_buffer = "".b

      raise(ArgumentError, "Buffer size cannot be smaller than 128") unless @buffer_size >= 128

      read_header
    end

    # Returns whether the stream being read is compressed
    #
    # Should be called before any reads are performed to determine if the file or
    # stream is compressed.
    #
    # Returns true when the header is present in the stream and it is compressed
    # Returns false when the header is present in the stream and it is not compressed
    # Returns nil when the header is not present in the stream
    #
    # Note: The file will not be decompressed automatically when compressed.
    #       To decompress the data automatically call SymmetricEncryption.open
    def compressed?
      @compressed
    end

    # Returns the Cipher encryption version used to encrypt this file
    # Returns nil when the header was not present in the stream and no :version
    #         option was supplied
    #
    # Note: When no header is present, the version is set to the one supplied
    #       in the options
    attr_reader :version

    # Close the IO Stream
    #
    # Note: Also closes the passed in io stream or file
    #
    # It is recommended to call Symmetric::EncryptedStream.open or Symmetric::EncryptedStream.io
    # rather than creating an instance of Symmetric::EncryptedStream directly to
    # ensure that the encrypted stream is closed before the stream itself is closed
    # Positional to match IO#close. Changing it to a keyword would break existing callers.
    def close(close_child_stream = true) # rubocop:disable Style/OptionalBooleanParameter
      return if closed?

      @ios.close if close_child_stream
      @closed = true
    end

    # Returns [true|false] whether this stream is closed.
    #
    # Note: Must be public. `.open` uses `respond_to?(:closed?)` to decide whether it can close
    #       the stream it created, since it can also be handed a Zlib::GzipReader.
    def closed?
      @closed || (@ios.respond_to?(:closed?) && @ios.closed?)
    end

    # Flush the read stream
    #  Needed by XLS gem
    def flush
      @ios.flush
    end

    # Return the size of the file rounded up to the nearest encryption block size
    #  Needed by XLS gem
    def size
      @ios.size
    end

    # Read from the stream and return the decrypted data
    # See IOS#read
    #
    # Reads at most length bytes from the I/O stream, or to the end of file if
    # length is omitted or is nil. length must be a non-negative integer or nil.
    #
    # At end of file, it returns nil if no more data is available, or the last
    # remaining bytes
    def read(length = nil, outbuf = nil)
      data             = outbuf.nil? ? +"" : outbuf.clear
      remaining_length = length

      until remaining_length&.zero? || eof?
        read_block(remaining_length) if @read_buffer.empty?

        if remaining_length && remaining_length < @read_buffer.length
          data << @read_buffer.slice!(0, remaining_length)
        else
          data << @read_buffer
          @read_buffer.clear
        end

        remaining_length = length - data.length if length
      end

      @pos += data.length
      data unless data.empty? && length&.positive?
    end

    # Reads a single decrypted line from the file up to and including the optional sep_string.
    # Raises EOFError on eof
    # The stream must be opened for reading or an IOError will be raised.
    def readline(sep_string = "\n")
      gets(sep_string) || raise(EOFError, "End of file reached when trying to read a line")
    end

    # Reads a single decrypted line from the file up to and including the optional sep_string.
    # A sep_string of nil reads the entire contents of the file
    # Returns nil on eof
    # The stream must be opened for reading or an IOError will be raised.
    def gets(sep_string, length = nil)
      return read(length) if sep_string.nil?

      # Read more data until we get the sep_string
      while (index = @read_buffer.index(sep_string)).nil? && more_to_decrypt?
        break if length && @read_buffer.length >= length

        read_block
      end
      index ||= -1
      data = @read_buffer.slice!(0..index)
      @pos += data.length
      return nil if data.empty? && eof?

      data
    end

    # ios.each(sep_string="\n") {|line| block } => ios
    # ios.each_line(sep_string="\n") {|line| block } => ios
    # Executes the block for every line in ios, where lines are separated by sep_string.
    # ios must be opened for reading or an IOError will be raised.
    def each_line(sep_string = "\n")
      yield gets(sep_string) until eof?
      self
    end

    alias each each_line

    # Returns whether the end of file has been reached for this stream
    #
    # A chunked stream reads ahead, so the encrypted buffer can still hold a chunk that has not
    # been decrypted yet after the underlying stream has been read to its end.
    def eof?
      @read_buffer.empty? && @encrypted_buffer.empty? && @ios.eof?
    end

    # Return the number of bytes read so far from the input stream
    attr_reader :pos

    # Rewind back to the beginning of the file
    def rewind
      @read_buffer.clear
      @encrypted_buffer.clear
      @ios.rewind
      read_header
    end

    # Seeks to a given offset (Integer) in the stream according to the value of whence:
    #  IO::SEEK_CUR  | Seeks to _amount_ plus current position
    #  --------------+----------------------------------------------------
    #  IO::SEEK_END  | Seeks to _amount_ plus end of stream (you probably
    #                | want a negative value for _amount_)
    #  --------------+----------------------------------------------------
    #  IO::SEEK_SET  | Seeks to the absolute location given by _amount_
    #
    # WARNING: IO::SEEK_SET will jump to the beginning of the file and
    #          then re-read upto the point specified
    # WARNING: IO::SEEK_END will read the entire file and then again
    #          upto the point specified
    def seek(amount, whence = IO::SEEK_SET)
      offset = 0
      case whence
      when IO::SEEK_SET
        offset = amount
        rewind
      when IO::SEEK_CUR
        if amount >= 0
          offset = amount
        else
          offset = @pos + amount
          rewind
        end
      when IO::SEEK_END
        rewind
        # Read and decrypt entire file a block at a time to get its total
        # unencrypted size
        size = 0
        until eof?
          read_block
          size += @read_buffer.size
          @read_buffer.clear
        end
        rewind
        offset = size + amount
      else
        raise(ArgumentError, "unknown whence:#{whence} supplied to seek()")
      end
      read(offset) if offset.positive?
      0
    end

    private

    # Returns [true|false] whether there is more encrypted data still to be decrypted.
    #
    # Not the same as `!eof?`, which is also false while the read buffer still holds decrypted
    # data. A chunked stream reads ahead, so the underlying stream reaches its end while a chunk
    # that has not been decrypted yet is still held.
    def more_to_decrypt?
      !@encrypted_buffer.empty? || !@ios.eof?
    end

    # Read the header from the file if present
    def read_header
      @pos              = 0
      @chunk_number     = 0
      @chunked_stream   = nil
      @encrypted_buffer = "".b

      # Read first block and check for the header
      buf = @ios.read(@buffer_size, @output_buffer ||= "".b)

      # Use cipher specified in header, or global cipher if it has no header
      iv, key, cipher_name, cipher = nil
      header                       = Header.new
      if header.parse!(buf)
        @header_present = true
        @compressed     = header.compressed?
        @version        = header.version
        cipher          = header.cipher
        cipher_name     = header.cipher_name || cipher.cipher_name
        key             = header.key
        iv              = header.iv
      else
        @header_present = false
        @compressed     = nil
        cipher          = SymmetricEncryption.cipher(@version)
        cipher_name     = cipher.cipher_name
      end

      @stream_cipher = ::OpenSSL::Cipher.new(cipher_name)
      return read_authenticated_header(header, cipher, cipher_name, key, buf) if @stream_cipher.authenticated?

      @stream_cipher.decrypt
      @stream_cipher.key = key || cipher.send(:key)
      @stream_cipher.iv  = iv || cipher.iv

      decrypt(buf)
    end

    # Prepares to read a stream that was encrypted with an authenticated cipher, in whichever of
    # the two forms `Writer` chose for it. See `Writer#initialize_authenticated`.
    def read_authenticated_header(header, cipher, cipher_name, key, buf)
      unless header.authenticated? || header.chunked?
        raise(
          SymmetricEncryption::CipherError,
          "Cipher #{cipher_name.inspect} is an authenticated cipher, but the stream has no auth tag. A stream " \
          "encrypted with an unauthenticated cipher has to be read with the cipher that encrypted it."
        )
      end

      @encrypted_buffer << buf if buf

      if header.chunked?
        @chunked_stream = ChunkedStream.new(
          cipher_name:  cipher_name,
          key:          key || cipher.send(:key),
          # The header of a chunked stream holds the prefix that every chunk's nonce is derived
          # from, rather than an iv used directly.
          nonce_prefix: header.iv,
          header_bytes: header.header_bytes,
          chunk_size:   header.chunk_size
        )
        read_chunk
      else
        read_single_authenticated(header, cipher_name, key, cipher)
      end
    end

    # Reads a stream small enough that `Writer` put its auth tag in the header rather than
    # chunking it. The whole stream has to be held before any of it can be verified, which is
    # exactly why anything larger is chunked, so the size is capped.
    def read_single_authenticated(header, cipher_name, key, cipher)
      limit = 2**Header::MAX_CHUNK_SIZE_EXPONENT
      while @encrypted_buffer.bytesize <= limit && !@ios.eof?
        @encrypted_buffer << @ios.read(@buffer_size, @output_buffer ||= "".b).to_s
      end

      if @encrypted_buffer.bytesize > limit
        raise(
          SymmetricEncryption::CipherError,
          "This stream holds its auth tag in its header, so all of it has to be read before any of it can be " \
          "verified, and it is larger than the #{limit} byte limit for that. A stream this size is written as a " \
          "chunked stream, which is verified as it is read."
        )
      end

      openssl_cipher = ::OpenSSL::Cipher.new(cipher_name)
      openssl_cipher.decrypt
      openssl_cipher.key = key || cipher.send(:key)
      openssl_cipher.iv  = header.iv
      openssl_cipher.auth_tag  = header.auth_tag
      openssl_cipher.auth_data = header.auth_data

      @read_buffer << openssl_cipher.update(@encrypted_buffer) unless @encrypted_buffer.empty?
      @read_buffer << openssl_cipher.final
      @encrypted_buffer.clear
    end

    # Reads and verifies the next chunk, appending its decrypted data to the read buffer.
    #
    # Whether a chunk is the last one is part of what it is authenticated against, so the next
    # byte after it has to be looked at before it can be decrypted. That is what stops a stream
    # being truncated: the chunk left at the end would have been encrypted as a middle chunk.
    def read_chunk
      frame_size = @chunked_stream.frame_size
      while (@encrypted_buffer.bytesize <= frame_size) && !@ios.eof?
        @encrypted_buffer << @ios.read([@buffer_size, frame_size].max, @output_buffer ||= "".b).to_s
      end
      return if @encrypted_buffer.empty?

      last  = @encrypted_buffer.bytesize <= frame_size
      frame = @encrypted_buffer.slice!(0, last ? @encrypted_buffer.bytesize : frame_size)

      @read_buffer << @chunked_stream.decrypt(@chunk_number, frame, last: last)
      @chunk_number += 1
    end

    # Read a block of data and append the decrypted data in the read buffer
    def read_block(length = nil)
      return read_chunk if @chunked_stream

      buf = @ios.read(length || @buffer_size, @output_buffer ||= "".b)
      decrypt(buf)
    end

    # Decrypts the given chunk of data and returns the result
    if defined?(JRuby)
      def decrypt(buf)
        return if buf.nil? || buf.empty?

        @read_buffer << @stream_cipher.update(buf)
        @read_buffer << @stream_cipher.final if @ios.eof?
      end
    else
      def decrypt(buf)
        return if buf.nil? || buf.empty?

        @read_buffer << @stream_cipher.update(buf, @cipher_buffer ||= "".b)
        @read_buffer << @stream_cipher.final if @ios.eof?
      end
    end
  end
end
