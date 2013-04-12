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
    #          If true, it forces header to true.
    #          Default: false
    #
    #     :random_key [true|false]
    #          Generates a new random key and iv for every new file or stream
    #          If true, it forces header to true. Version below then has no effect
    #          The Random key and iv will be written to the file/stream in encrypted
    #          form as part of the header
    #          The key and iv are both encrypted using the global key
    #          Default: true
    #          Recommended: true. Setting to false will eventually expose the
    #            encryption key since too much data will be encrypted using the
    #            same encryption key
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
    #          When random_key is true, the version of the encryption key to use
    #          when encrypting the header portion of the file
    #
    #          When random_key is false, the version of the encryption key to use
    #          to encrypt the entire file
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
      @ios       = ios
      header     = options.fetch(:header, true)
      # Compress is only used at this point for setting the flag in the header
      random_key = options.fetch(:random_key, true)
      random_iv  = options.fetch(:random_iv, true)
      compress   = options.fetch(:compress, false)
      # Force header if compressed or using random iv, key pair
      header     = true if compress || random_key

      # Create random cipher or use global primary cipher
      @cipher = random_key ? SymmetricEncryption::Cipher.random_cipher : SymmetricEncryption.cipher(options[:version])
      raise "Cipher with version:#{options[:version]} not found in any of the configured SymmetricEncryption ciphers" unless @cipher

      @stream_cipher = @cipher.send(:openssl_cipher, :encrypt)

      # Write the Encryption header including the random iv, key, and cipher
      if header || random_key || random_iv || compress
        @ios.write(@cipher.magic_header(compress,
            random_key ? @cipher.send(:key) : nil,
            random_iv  ? @cipher.send(:iv) : nil,
            (random_key || random_iv) ? @cipher.cipher : nil))
      end
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

  end
end
