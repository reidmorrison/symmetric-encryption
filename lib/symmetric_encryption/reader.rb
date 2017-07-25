require 'openssl'

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
    def self.open(file_name_or_stream, buffer_size: 16384, **args, &block)
      ios = file_name_or_stream.is_a?(String) ? ::File.open(file_name_or_stream, 'rb') : file_name_or_stream

      begin
        file = self.new(ios, buffer_size: buffer_size, **args)
        file = Zlib::GzipReader.new(file) if !file.eof? && file.compressed?
        block ? block.call(file) : file
      ensure
        file.close if block && file && (file.respond_to?(:closed?) && !file.closed?)
      end
    end

    # Read the entire contents of a file or stream into memory.
    #
    # Notes:
    # * Do not use this method for reading large files.
    def self.read(file_name_or_stream, **args)
      open(file_name_or_stream, **args) { |f| f.read }
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
    #   block_size: [Integer]
    #     Number of bytes to read into memory for each read.
    #     For very large files using a larger block size is faster.
    #     Default: 65535
    #
    # Notes:
    # * The file contents are streamed so that the entire file is _not_ loaded into memory.
    def self.decrypt(source:, target:, block_size: 65535, **args)
      target_ios    = target.is_a?(String) ? ::File.open(target, 'wb') : target
      bytes_written = 0
      open(source, **args) do |input_ios|
        while !input_ios.eof?
          bytes_written += target_ios.write(input_ios.read(block_size))
        end
      end
      bytes_written
    ensure
      target_ios.close if target_ios && target_ios.respond_to?(:closed?) && !target_ios.closed?
    end

    # Returns [true|false] whether the file or stream contains any data
    # excluding the header should it have one
    def self.empty?(file_name_or_stream)
      open(file_name_or_stream) { |file| file.eof? }
    end

    # Returns [true|false] whether the file contains the encryption header
    def self.header_present?(file_name)
      ::File.open(file_name, 'rb') { |file| new(file).header_present? }
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
      @version        = version
      @header_present = false
      @closed         = false

      raise(ArgumentError, 'Buffer size cannot be smaller than 128') unless @buffer_size >= 128

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
    def version
      @version
    end

    # Close the IO Stream
    #
    # Note: Also closes the passed in io stream or file
    #
    # It is recommended to call Symmetric::EncryptedStream.open or Symmetric::EncryptedStream.io
    # rather than creating an instance of Symmetric::EncryptedStream directly to
    # ensure that the encrypted stream is closed before the stream itself is closed
    def close(close_child_stream = true)
      return if closed?
      @ios.close if close_child_stream
      @closed = true
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
    def read(length=nil)
      data = nil
      if length
        return '' if length == 0
        return nil if eof?
        # Read length bytes
        while (@read_buffer.length < length) && !@ios.eof?
          read_block
        end
        if @read_buffer.length == 0
          data = nil
        elsif @read_buffer.length > length
          data = @read_buffer.slice!(0..length-1)
        else
          data         = @read_buffer
          @read_buffer = ''
        end
      else
        # Capture anything already in the buffer
        data         = @read_buffer
        @read_buffer = ''

        if !@ios.eof?
          # Read entire file
          buf = @ios.read || ''
          data << @stream_cipher.update(buf) if buf && buf.length > 0
          data << @stream_cipher.final
        end
      end
      @pos += data.length
      data
    end

    # Reads a single decrypted line from the file up to and including the optional sep_string.
    # Raises EOFError on eof
    # The stream must be opened for reading or an IOError will be raised.
    def readline(sep_string = "\n")
      gets(sep_string) || raise(EOFError.new('End of file reached when trying to read a line'))
    end

    # Reads a single decrypted line from the file up to and including the optional sep_string.
    # A sep_string of nil reads the entire contents of the file
    # Returns nil on eof
    # The stream must be opened for reading or an IOError will be raised.
    def gets(sep_string, length=nil)
      return read(length) if sep_string.nil?

      # Read more data until we get the sep_string
      while (index = @read_buffer.index(sep_string)).nil? && !@ios.eof?
        break if length && @read_buffer.length >= length
        read_block
      end
      index ||= -1
      data  = @read_buffer.slice!(0..index)
      @pos  += data.length
      return nil if data.length == 0 && eof?
      data
    end

    # ios.each(sep_string="\n") {|line| block } => ios
    # ios.each_line(sep_string="\n") {|line| block } => ios
    # Executes the block for every line in ios, where lines are separated by sep_string.
    # ios must be opened for reading or an IOError will be raised.
    def each_line(sep_string = "\n")
      while !eof?
        yield gets(sep_string)
      end
      self
    end

    alias_method :each, :each_line

    # Returns whether the end of file has been reached for this stream
    def eof?
      (@read_buffer.size == 0) && @ios.eof?
    end

    # Return the number of bytes read so far from the input stream
    def pos
      @pos
    end

    # Rewind back to the beginning of the file
    def rewind
      @read_buffer = ''
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
    def seek(amount, whence=IO::SEEK_SET)
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
        while !eof
          read_block
          size         += @read_buffer.size
          @read_buffer = ''
        end
        rewind
        offset = size + amount
      else
        raise(ArgumentError, "unknown whence:#{whence} supplied to seek()")
      end
      read(offset) if offset > 0
      0
    end

    private

    # Read the header from the file if present
    def read_header
      @pos = 0

      # Read first block and check for the header
      buf = @ios.read(@buffer_size)

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
      @stream_cipher.decrypt
      @stream_cipher.key = key || cipher.send(:key)
      @stream_cipher.iv  = iv || cipher.iv

      # First call to #update should return an empty string anyway
      if buf && buf.length > 0
        @read_buffer = @stream_cipher.update(buf)
        @read_buffer << @stream_cipher.final if @ios.eof?
      else
        @read_buffer = ''
      end
    end

    # Read a block of data and append the decrypted data in the read buffer
    def read_block
      buf = @ios.read(@buffer_size)
      @read_buffer << @stream_cipher.update(buf) if buf && buf.length > 0
      @read_buffer << @stream_cipher.final if @ios.eof?
    end

    def closed?
      @closed || @ios.respond_to?(:closed?) && @ios.closed?
    end

  end
end
