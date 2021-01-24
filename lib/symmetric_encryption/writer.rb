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
        file_name_or_stream = ::File.open(file_name_or_stream, "wb")
        compress            = !(/\.(zip|gz|gzip|xls.|)\z/i === file_name_or_stream) if compress.nil?
      elsif compress.nil?
        compress = true
      end

      begin
        file = new(file_name_or_stream, compress: compress, **args)
        file = Zlib::GzipWriter.new(file) if compress
        block_given? ? yield(file) : file
      ensure
        file.close if block_given? && file && (file.respond_to?(:closed?) && !file.closed?)
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
    #     Default: false
    #
    # Notes:
    # * The file contents are streamed so that the entire file is _not_ loaded into memory.
    def self.encrypt(source:, target:, **args)
      Writer.open(target, **args) { |output_file| IO.copy_stream(source, output_file) }
    end

    # Encrypt data before writing to the supplied stream
    def initialize(ios, version: nil, cipher_name: nil, header: true, random_key: true, random_iv: true, compress: false)
      # Compress is only used at this point for setting the flag in the header
      @ios = ios
      raise(ArgumentError, "When :random_key is true, :random_iv must also be true") if random_key && !random_iv
      if cipher_name && !random_key && !random_iv
        raise(ArgumentError, "Cannot supply a :cipher_name unless both :random_key and :random_iv are true")
      end

      # Cipher to encrypt the random_key, or the entire file
      cipher = SymmetricEncryption.cipher(version)
      unless cipher
        raise(SymmetricEncryption::CipherError,
              "Cipher with version:#{version} not found in any of the configured SymmetricEncryption ciphers")
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

      @size   = 0
      @closed = false
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
    def close(close_child_stream = true)
      return if closed?

      if size.positive?
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

        bytes = data.to_s
        @size += bytes.size
        partial = @stream_cipher.update(bytes)
        @ios.write(partial) unless partial.empty?
        data.length
      end
    else
      def write(data)
        return unless data

        bytes = data.to_s
        @size += bytes.size
        partial = @stream_cipher.update(bytes, @cipher_buffer ||= "".b)
        @ios.write(partial) unless partial.empty?
        data.length
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
      @closed || @ios.respond_to?(:closed?) && @ios.closed?
    end

    # Returns [Integer] the number of unencrypted and uncompressed bytes
    # written to the file so far.
    attr_reader :size
  end
end
