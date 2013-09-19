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
    #   filename_or_stream:
    #     The filename to open if a string, otherwise the stream to use
    #     The file or stream will be closed on completion, use .initialize to
    #     avoid having the stream closed automatically
    #
    #   options:
    #     :mode
    #          See File.open for open modes
    #          Default: 'rb'
    #
    #     :buffer_size
    #          Amount of data to read at a time
    #          Minimum Value 128
    #          Default: 4096
    #
    #   The following options are only used if the stream/file has no header
    #     :compress [true|false]
    #          Uses Zlib to decompress the data after it is decrypted
    #          Note: This option is only used if the file does not have a header
    #                indicating whether it is compressed
    #          Default: false
    #
    #     :version
    #          Version of the encryption key to use when decrypting and the
    #          file/stream does not include a header at the beginning
    #          Default: Current primary key
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
    # SymmetricEncryption::Reader.open('encrypted_compressed.zip', :compress => true) do |file|
    #   file.each_line {|line| p line }
    # end
    #
    # # Example: Reading from a CSV file
    #
    # require 'fastercsv'
    # begin
    #   csv = FasterCSV.new(SymmetricEncryption::Reader.open('csv_encrypted'))
    #   csv.each {|row| p row}
    # ensure
    #   csv.close if csv
    # end
    def self.open(filename_or_stream, options={}, &block)
      raise "options must be a hash" unless options.respond_to?(:each_pair)
      mode     = options.fetch(:mode, 'rb')
      compress = options.fetch(:compress, false)
      ios      = filename_or_stream.is_a?(String) ? ::File.open(filename_or_stream, mode) : filename_or_stream

      begin
        file = self.new(ios, options)
        file = Zlib::GzipReader.new(file) if !file.eof? && (file.compressed? || compress)
        block ? block.call(file) : file
      ensure
        file.close if block && file
      end
    end

    # Returns [true|false] whether the file or stream contains any data
    # excluding the header should it have one
    def self.empty?(filename_or_stream)
      open(filename_or_stream) {|file| file.eof? }
    end

    # Returns [true|false] whether the file contains the encryption header
    def self.header_present?(filename)
      ::File.open(filename, 'rb') {|file| new(file).header_present?}
    end

    # After opening a file Returns [true|false] whether the file being
    # read has an encryption header
    def header_present?
      @header_present
    end

    # Decrypt data before reading from the supplied stream
    def initialize(ios,options={})
      @ios            = ios
      @buffer_size    = options.fetch(:buffer_size, 4096).to_i
      @version        = options[:version]
      @header_present = false

      raise "Buffer size cannot be smaller than 128" unless @buffer_size >= 128

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
      @ios.close if close_child_stream
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
        return nil if @ios.eof? && (@read_buffer.length == 0)
        # Read length bytes
        while (@read_buffer.length < length) && !@ios.eof?
          read_block
        end
        if @read_buffer.length > length
          data = @read_buffer.slice!(0..length-1)
        else
          data = @read_buffer
          @read_buffer = ''
        end
      else
        # Capture anything already in the buffer
        data = @read_buffer
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
      gets(sep_string) || raise(EOFError.new("End of file reached when trying to read a line"))
    end

    # Reads a single decrypted line from the file up to and including the optional sep_string.
    # A sep_string of nil reads the entire contents of the file
    # Returns nil on eof
    # The stream must be opened for reading or an IOError will be raised.
    def gets(sep_string,length=nil)
      return read(length) if sep_string.nil?

      # Read more data until we get the sep_string
      while (index = @read_buffer.index(sep_string)).nil? && !@ios.eof?
        break if length && @read_buffer.length >= length
        read_block
      end
      index ||= -1
      data = @read_buffer.slice!(0..index)
      @pos += data.length
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
          size += @read_buffer.size
          @read_buffer = ''
        end
        rewind
        offset = size + amount
      else
        raise "unknown whence:#{whence} supplied to seek()"
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
      iv, key, cipher_name, decryption_cipher = nil
      if header = SymmetricEncryption::Cipher.parse_header!(buf)
        @header_present   = true
        @compressed       = header.compressed
        decryption_cipher = header.decryption_cipher
        cipher_name       = header.cipher_name || decryption_cipher.cipher_name
        key               = header.key
        iv                = header.iv
      else
        @header_present   = false
        @compressed       = nil
        decryption_cipher = SymmetricEncryption.cipher(@version)
        cipher_name       = decryption_cipher.cipher_name
      end

      @stream_cipher = ::OpenSSL::Cipher.new(cipher_name)
      @stream_cipher.decrypt
      @stream_cipher.key = key || decryption_cipher.send(:key)
      @stream_cipher.iv = iv || decryption_cipher.iv

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

  end
end
