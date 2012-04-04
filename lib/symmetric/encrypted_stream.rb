# require 'forwardable'
require 'zlib'
module Symmetric
  class EncryptedStream
    # Read and Write to encrypted files and other IO streams
    #
    # Features:
    # * Encryption and decryption on the fly whilst reading or writing files.
    # * Large file support by only buffering small amounts of data in memory
    # * Underlying buffering to ensure that encrypted and decrypted data fits
    #   into the Symmetric Encryption Cipher block size
    #   Only the last block in the file will be padded if it is less than the block size
    #
    # # Example: Encrypt and write data to a file
    # Symmetric::EncryptedStream.open('test_file','w') do |file|
    #   file.write "Hello World\n"
    #   file.write "Keep this secret"
    # end
    #
    # # Example: Read and decrypt a line at a time from a file
    # Symmetric::EncryptedStream.open('test_file','r') do |file|
    #   file.each_line {|line| p line }
    # end
    #
    # # Example: Read and decrypt entire file in memory
    # Symmetric::EncryptedStream.open('test_file','r') {|f| f.read }
    #
    # # Example: Reading a limited number of bytes from the file
    # Symmetric::EncryptedStream.open('test_file','r', options) do |file|
    #   file.read(1)
    #   file.read(5)
    #   file.read
    # end
    #
    # # Example: Read and decrypt 5 bytes at a time until the end of file is reached
    # Symmetric::EncryptedStream.open('test_file','r') do |file|
    #   while !file.eof? do
    #     file.read(5)
    #   end
    # end
    #
    # # Example: Compress, Encrypt and write data to a file
    # Symmetric::EncryptedStream.open('encrypted_compressed.zip','w', :compress => true) do |file|
    #   file.write "Hello World\n"
    #   file.write "Compress this\n"
    #   file.write "Keep this safe and secure\n"
    # end
    #
    # # Example: Read, Unencrypt and decompress data in a file
    # Symmetric::EncryptedStream.open('encrypted_compressed.zip','r', :compress => true) do |file|
    #   file.each_line {|line| p line }
    # end


    # Open a file, or use the supplied IO Stream
    # Parameters:
    #   io:
    #     The filename to open
    #   mode:
    #     See File.open for open modes
    #
    #   options:
    #     :compress [true|false]
    #          Uses Zlib to decompress the data after it is decrypted,
    #          or compress it before it is encrypted and written to the file
    #          Default: false
    #
    #     :header [true|false]
    #          Whether to include the magic header that indicates the file
    #          is encrypted and whether its contents are compressed
    #          Only used on write. During the read the header is always
    #          autodetected and any supplied options overridden by the file
    #          header if present.
    #
    #          The header contains:
    #             Version of the encryption key used to encrypt the file
    #             Indicator if the data was compressed
    #          Default: true
    #
    #     :version
    #          Version of the encryption key to use when encrypting
    #          During decryption this value is only used if the file does
    #          not contain the Symmetric::Encryption header
    #          Default: Current primary key
    #
    # Note: When writing compression occurs before encryption
    #       When reading decryption occurs before decompression
    #
    def self.open(filename, mode='r', options={}, &block)
      if options[:compress] == true
        begin
          if mode.include?('r')
            file = Zlib::GzipReader.new(self.new(::File.open(filename, mode), options))
          else
            file = Zlib::GzipWriter.new(self.new(::File.open(filename, mode), options))
          end
          block.call(file)
        ensure
          file.close
        end
      else
        self.stream(::File.open(filename, mode), options, &block)
      end
    end

    # Use the supplied IO stream to read or write, decrypting or encrypting as
    # applicable
    #
    # Parameters:
    #   io:
    #     The IO or File to read/write
    #
    # Note: The option :compress is not currently support by Symmetric::Encryption.stream
    #       Zlib needs to know if it is a read or write stream whereas
    #       Symmetric::Encryption.stream does not impose any such limitation
    #
    def self.stream(ios, options={}, &block)
      raise ":compress option not supported by Symmetric::Encryption.stream" if options[:compress] == true
      begin
        encrypted_stream = self.new(ios, options)
        block.call(encrypted_stream)
      ensure
        encrypted_stream.close if encrypted_stream
      end
    end

    # Create an Encrypted IO Stream from another IO stream
    def initialize(ios,options={})
      @ios    = ios
      @header = options.fetch(:header, false)
      @compress = options.fetch(:compress, false)

      # Use primary cipher by default
      @cipher = Encryption.cipher

      # Allow a specific cipher to be selected for encryption
      if @version = options[:version]
        unless @cipher.version == @version
          @cipher = secondary_ciphers.find {|c| c.version == @version}
          raise "Cipher with version:#{@version} not found in any of the configured Symmetric::Encryption ciphers" unless @cipher
        end
      end
      # Set header as written when no header required
      @header_written = !@header

      # Need to encrypt data in blocks, so buffer data until it reaches the block_size
      @write_buffer = ''
      @read_buffer = ''
      # Encrypt/decrypt 4K at a time
      @block_size = (256 * @cipher.block_size) - 1
    end

    # Close the IO Stream
    # Flushes any unwritten data
    #
    # Note: Also closes the passed in io stream or file
    # Note: This method must be called _before_ the supplied stream is closed
    #
    # It is recommended to call Symmetric::EncryptedStream.open or Symmetric::EncryptedStream.io
    # rather than creating an instance of Symmetric::EncryptedStream directly to
    # ensure that the encrypted stream is closed before the stream itself is closed
    def close
      if @write_buffer.length > 0
        @ios.write(@cipher.encrypt(@write_buffer))
        @write_buffer = ''
      end
      @ios.close
    end

    # Decrypt data and write to the IO Stream
    # read(length=nil, buffer=nil) => string, buffer, or nil
    # See IOS#read
    #
    # Reads at most length bytes from the I/O stream, or to the end of file if
    # length is omitted or is nil. length must be a non-negative integer or nil.
    # If the optional buffer argument is present, it must reference a String,
    # which will receive the data.
    #
    # At end of file, it returns nil or "" depend on length.
    # ios.read() and ios.read(nil) returns "".
    # ios.read(positive-integer) returns nil.
    def read(length=nil) #, buffer=nil)
      data = nil
      if length
        # Read length bytes
        if @read_buffer.length >= length
          data = @read_buffer.slice!(0..length-1)
        else
          while (@read_buffer.length < length) && !@ios.eof?
            read_block
          end
          if @read_buffer.length >= length
            data = @read_buffer.slice!(0..length-1)
          else
            data = @read_buffer
            @read_buffer = ''
          end
        end
      else
        # Capture anything already in the buffer
        data = @read_buffer
        @read_buffer = ''

        # Read entire file
        buf = @ios.read || ''
        index = 0
        while index < buf.length
          data << @cipher.decrypt(buf[index..index+@block_size])
          index += @block_size+1
        end
      end
      data
    end

    # Reads a single decrypted line from the file up to and including the optional sep_string.
    # Returns nil on eof
    # The stream must be opened for reading or an IOError will be raised.
    def readline(sep_string = "\n")
      # Read more data until we get the sep_string
      while (index = @read_buffer.index(sep_string)).nil? && !@ios.eof
        read_block
      end
      index ||= -1
      @read_buffer.slice!(0..index)
    end

    # ios.each(sep_string="\n") {|line| block } => ios
    # ios.each_line(sep_string="\n") {|line| block } => ios
    # Executes the block for every line in ios, where lines are separated by sep_string.
    # ios must be opened for reading or an IOError will be raised.
    def each_line(sep_string = "\n")
      while !eof?
        yield readline(sep_string)
      end
      self
    end

    alias_method :each, :each_line

    # Returns whether the end of file has been reached for this stream
    def eof?
      (@read_buffer.size == 0) && @ios.eof?
    end

    # Write to the IO Stream as encrypted data
    # Returns the number of bytes written
    def write(data)
      write_header unless @header_written
      @write_buffer << data.to_s

      # Check if there is sufficient data to start writing
      while @write_buffer.length >= @block_size
        buffer = @write_buffer.slice!(0..@block_size-1)
        puts "Write Clear: [#{buffer.inspect}](#{buffer.length}), Buffered: [#{@write_buffer.inspect}]"
        encrypted = @cipher.encrypt(buffer)
        @ios.write(encrypted)
        puts "Write Encrypted: [#{encrypted.inspect}](#{encrypted.length})]"
      end

      data.length
    end

    private

    # Binary encrypted data includes this magic header so that we can quickly
    # identify binary data versus base64 encoded data that does not have this header
    unless defined? MAGIC_HEADER
      MAGIC_HEADER = '@EnC'
      MAGIC_HEADER_SIZE = MAGIC_HEADER.size
      MAGIC_HEADER_UNPACK = "A#{MAGIC_HEADER_SIZE}v"
    end

    # Write the Encryption header if this is the first write
    def write_header
      # Include Header and encryption version indicator
      flags  = @cipher.version || 0 # Same as 0b0000_0000_0000_0000

      # If the data is to be compressed before being encrypted, set the
      # compressed bit in the version byte
      flags |= 0b1000_0000_0000_0000 if @compress

      @ios.write "#{MAGIC_HEADER}#{[flags].pack('v')}"

      @header_written = true
    end

    # Read the Encryption header if this is the first read
    # If the header is present, then that many bytes
    # will be read from the stream so that subsequent block reads will align
    def read_block
      # Read a single block from the stream
      buf = @ios.read(@block_size+1)

      if !@header_read && buf.start_with?(MAGIC_HEADER)
        # Header includes magic header and version byte
        # Remove header and extract flags
        header, flags = buf.slice!(0..MAGIC_HEADER_SIZE).unpack(MAGIC_HEADER_UNPACK)
        @compressed = flags & 0b1000_0000_0000_0000
        @header_read = true
        # Read header size more bytes including version number
        buf << @ios.read(MAGIC_HEADER_SIZE+1)
      end
      @read_buffer << @cipher.decrypt(buf)
    end

  end
end
