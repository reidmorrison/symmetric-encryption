module SymmetricEncryption
  # Write to encrypted files and other IO streams
  #
  # Features:
  # * Encryption on the fly whilst writing files.
  # * Large file support by only buffering small amounts of data in memory
  # * Underlying buffering to ensure that encrypted data fits
  #   into the Symmetric Encryption Cipher block size
  #   Only the last block in the file will be padded if it is less than the block size
  class Writer
    # Open a file for writing, or use the supplied IO Stream
    #
    # Parameters:
    #   filename_or_stream:
    #     The filename to open if a string, otherwise the stream to use
    #     The file or stream will be closed on completion, use .initialize to
    #     avoid having the stream closed automatically
    #
    #   options:
    #     :compress [true|false]
    #          Uses Zlib to compress the data before it is encrypted and
    #          written to the file
    #          Default: false
    #
    #     :header [true|false]
    #          Whether to include the magic header that indicates the file
    #          is encrypted and whether its contents are compressed
    #
    #          The header contains:
    #             Version of the encryption key used to encrypt the file
    #             Indicator if the data was compressed
    #          Default: true
    #
    #     :version
    #          Version of the encryption key to use when encrypting
    #          Default: Current primary key
    #
    #     :mode
    #          See File.open for open modes
    #          Default: 'w'
    #
    # Note: Compression occurs before encryption
    #
    #
    # # Example: Encrypt and write data to a file
    # SymmetricEncryption::Writer.open('test_file') do |file|
    #   file.write "Hello World\n"
    #   file.write "Keep this secret"
    # end
    #
    # # Example: Compress, Encrypt and write data to a file
    # SymmetricEncryption::Writer.open('encrypted_compressed.zip', :compress => true) do |file|
    #   file.write "Hello World\n"
    #   file.write "Compress this\n"
    #   file.write "Keep this safe and secure\n"
    # end
    #
    # # Example: Writing to a CSV file
    #  require 'fastercsv'
    #  begin
    #    # Must supply :row_sep for FasterCSV otherwise it will attempt to read from and then rewind the file
    #    csv = FasterCSV.new(SymmetricEncryption::Writer.open('csv_encrypted'), :row_sep => "\n")
    #    csv << [1,2,3,4,5]
    #  ensure
    #    csv.close if csv
    #  end
    def self.open(filename_or_stream, options={}, &block)
      raise "options must be a hash" unless options.respond_to?(:each_pair)
      mode = options.fetch(:mode, 'wb')
      compress = options.fetch(:compress, false)
      ios = filename_or_stream.is_a?(String) ? ::File.open(filename_or_stream, mode) : filename_or_stream

      begin
        file = self.new(ios, options)
        file = Zlib::GzipWriter.new(file) if compress
        block ? block.call(file) : file
      ensure
        file.close if block && file
      end
    end

    # Encrypt data before writing to the supplied stream
    def initialize(ios,options={})
      @ios      = ios
      header    = options.fetch(:header, true)
      # Compress is only used at this point for setting the flag in the header
      @compress = options.fetch(:compress, false)

      # Use primary cipher by default, but allow a secondary cipher to be selected for encryption
      @cipher   = SymmetricEncryption.cipher(options[:version])
      raise "Cipher with version:#{options[:version]} not found in any of the configured SymmetricEncryption ciphers" unless @cipher

      @stream_cipher = @cipher.send(:openssl_cipher, :encrypt)

      write_header if header
    end

    # Close the IO Stream
    # Flushes any unwritten data
    #
    # Note: Once an EncryptionWriter has been closed a new instance must be
    #       created before writing again
    #
    # Note: Also closes the passed in io stream or file
    # Note: This method must be called _before_ the supplied stream is closed
    #
    # It is recommended to call Symmetric::EncryptedStream.open
    # rather than creating an instance of Symmetric::EncryptedStream directly to
    # ensure that the encrypted stream is closed before the stream itself is closed
    def close(close_child_stream = true)
      final = @stream_cipher.final
      @ios.write(final) if final.length > 0
      @ios.close if close_child_stream
    end

    # Write to the IO Stream as encrypted data
    # Returns the number of bytes written
    def write(data)
      partial = @stream_cipher.update(data.to_s)
      @ios.write(partial) if partial.length > 0
      data.length
    end

    # Write to the IO Stream as encrypted data
    # Returns self
    #
    # Example:
    #   file << "Hello.\n" << "This is Jack"
    def <<(data)
      write(data)
      self
    end

    # Flush the output stream
    # Does not flush internal buffers since encryption requires all data to
    # be written following the encryption block size
    #  Needed by XLS gem
    def flush
      @ios.flush
    end

    private

    # Write the Encryption header if this is the first write
    def write_header
      # Include Header and encryption version indicator
      flags  = @cipher.version || 0 # Same as 0b0000_0000_0000_0000

      # If the data is to be compressed before being encrypted, set the
      # compressed bit in the version byte
      flags |= 0b1000_0000_0000_0000 if @compress

      @ios.write "#{MAGIC_HEADER}#{[flags].pack('v')}"
    end

  end
end
