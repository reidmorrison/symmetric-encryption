require_relative "test_helper"
require "stringio"

# Unit Test for SymmetricEncrypted::ReaderStream
#
class ReaderTest < Minitest::Test
  describe SymmetricEncryption::Reader do
    before do
      @data = [
        "Hello World\n",
        "Keep this secret\n",
        "And keep going even further and further..."
      ]
      @data_str = @data.inject(+"") { |sum, str| sum << str }
      @data_len = @data_str.length
      # Use Cipher 0 since it does not always include a header
      @cipher = SymmetricEncryption.cipher(0)
      @data_encrypted_without_header = @cipher.binary_encrypt(@data_str, header: false)

      header = SymmetricEncryption::Header.new(
        version:     @cipher.version,
        iv:          @cipher.iv,
        key:         @cipher.send(:key),
        cipher_name: @cipher.cipher_name
      )
      @data_encrypted_with_header = @cipher.binary_encrypt(@data_str, header: header)

      # Verify regular decrypt can decrypt this string
      @cipher.binary_decrypt(@data_encrypted_without_header)
      @cipher.binary_decrypt(@data_encrypted_with_header)

      refute_equal @data_encrypted_without_header, @data_encrypted_with_header
    end

    [true, false].each do |header|
      describe header do
        before do
          @data_encrypted = header ? @data_encrypted_with_header : @data_encrypted_without_header
        end

        it "#read()" do
          stream = StringIO.new(@data_encrypted)
          # Version 0 supplied if the file/stream does not have a header
          decrypted = SymmetricEncryption::Reader.open(stream, version: 0, &:read)

          assert_equal @data_str, decrypted
        end

        it "#read(size) followed by #read()" do
          stream = StringIO.new(@data_encrypted)
          # Version 0 supplied if the file/stream does not have a header
          decrypted = SymmetricEncryption::Reader.open(stream, version: 0) do |file|
            file.read(10)
            file.read
          end

          assert_equal @data_str[10..], decrypted
        end

        it "#each_line" do
          stream = StringIO.new(@data_encrypted)
          i      = 0
          # Version 0 supplied if the file/stream does not have a header
          SymmetricEncryption::Reader.open(stream, version: 0) do |file|
            file.each_line do |line|
              assert_equal @data[i], line
              i += 1
            end
          end
        end

        it "#read(size)" do
          stream = StringIO.new(@data_encrypted)
          # Version 0 supplied if the file/stream does not have a header
          SymmetricEncryption::Reader.open(stream, version: 0) do |file|
            index = 0
            [0, 10, 5, 5000].each do |size|
              buf = file.read(size)
              if size.zero?
                assert_equal "", buf
              else
                assert_equal @data_str[index..(index + size - 1)], buf
              end
              index += size
            end
          end
        end
      end
    end

    [
      # No Header
      {header: false, random_key: false, random_iv: false, compress: false},
      # Default Header with random key and iv
      {},
      # Header with no compression ( default anyway )
      {compress: false},
      # Compress and use Random key, iv
      {compress: true},
      # Header but not random key or iv
      {random_key: false},
      # Random iv only
      {random_key: false, random_iv: true},
      # Random iv only with compression
      {random_iv: true, compress: true}
    ].each do |options|
      %i[data empty blank].each do |usecase|
        describe "read from #{usecase} file with options: #{options.inspect}" do
          before do
            case usecase
            when :data
              # Create encrypted file
              @eof       = false
              @file_name = "_test"
              @header    = (options[:header] != false)
              SymmetricEncryption::Writer.open(@file_name, **options) do |file|
                @data.inject(0) { |sum, str| sum + file.write(str) }
              end
            when :empty
              @data_str  = ""
              @eof       = true
              @file_name = "_test_empty"
              @header    = (options[:header] != false)
              SymmetricEncryption::Writer.open(@file_name, **options) do |file|
                # Leave data portion empty
              end
            when :blank
              @data_str  = ""
              @eof       = true
              @file_name = File.join(File.dirname(__FILE__), "config/empty.csv")
              @header    = false

              assert_equal 0, File.size(@file_name)
            else
              raise "Unhandled usecase: #{usecase}"
            end
            @data_size = @data_str.length
          end

          after do
            File.delete(@file_name) if File.exist?(@file_name) && !@file_name.end_with?("empty.csv")
          end

          it ".empty?" do
            assert_equal @data_size.zero?, SymmetricEncryption::Reader.empty?(@file_name)
            assert_raises Errno::ENOENT do
              SymmetricEncryption::Reader.empty?("missing_file")
            end
          end

          it ".header_present?" do
            assert_equal @header, SymmetricEncryption::Reader.header_present?(@file_name)
            assert_raises Errno::ENOENT do
              SymmetricEncryption::Reader.header_present?("missing_file")
            end
          end

          it ".open return Zlib::GzipReader when compressed" do
            file = SymmetricEncryption::Reader.open(@file_name)
            # assert_equal (@header && (options[:compress]||false)), file.is_a?(Zlib::GzipReader)
            file.close
          end

          it "#read" do
            data   = nil
            eof    = nil
            result = SymmetricEncryption::Reader.open(@file_name) do |file|
              eof  = file.eof?
              data = file.read
            end

            assert_equal @eof, eof
            assert_equal @data_str, data
            assert_equal @data_str, result
          end

          it "#read(size)" do
            file = SymmetricEncryption::Reader.open(@file_name)
            eof  = file.eof?
            data = file.read(4096)
            file.close

            assert_equal @eof, eof
            if @data_size.positive?
              assert_equal @data_str, data
            else
              assert_nil data
            end
          end

          it "#read(size, outbuf)" do
            file = SymmetricEncryption::Reader.open(@file_name)
            # Not supported with compressed files
            if file.is_a?(SymmetricEncryption::Reader)
              eof           = file.eof?
              output_buffer = +"buffer"
              data          = file.read(4096, output_buffer)
              file.close

              assert_equal @eof, eof
              if @data_size.positive?
                assert_equal @data_str, data
                assert_same data, output_buffer
              else
                assert_nil data
                assert_empty output_buffer
              end
            end
          end

          it "#each_line" do
            SymmetricEncryption::Reader.open(@file_name) do |file|
              i = 0
              file.each_line do |line|
                assert_equal @data[i], line
                i += 1
              end
            end
          end

          it "#rewind" do
            decrypted = SymmetricEncryption::Reader.open(@file_name) do |file|
              file.read
              file.rewind
              file.read
            end

            assert_equal @data_str, decrypted
          end

          it "#gets(nil,size)" do
            file = SymmetricEncryption::Reader.open(@file_name)
            eof  = file.eof?
            data = file.gets(nil, 4096)
            file.close

            assert_equal @eof, eof
            if @data_size.positive?
              assert_equal @data_str, data
            elsif defined?(JRuby)
              # On JRuby Zlib::GzipReader.new(file) returns '' instead of nil on an empty file
              assert_predicate data, :blank?
            else
              assert_nil data
            end
          end

          it "#gets(delim)" do
            SymmetricEncryption::Reader.open(@file_name) do |file|
              i = 0
              while (line = file.gets("\n"))
                assert_equal @data[i], line
                i += 1
              end

              assert_equal (@data_size.positive? ? 3 : 0), i
            end
          end

          it "#gets(delim,size)" do
            SymmetricEncryption::Reader.open(@file_name) do |file|
              i = 0
              i += 1 while file.gets("\n", 128)

              assert_equal (@data_size.positive? ? 3 : 0), i
            end
          end
        end
      end
    end

    describe "reading from files with previous keys" do
      before do
        @file_name = "_test"
        # Create encrypted file with old encryption key
        SymmetricEncryption::Writer.open(@file_name, version: 0) do |file|
          @data.inject(0) { |sum, str| sum + file.write(str) }
        end
      end

      after do
        FileUtils.rm_f(@file_name)
      end

      it "decrypt from file in a single read" do
        decrypted = SymmetricEncryption::Reader.open(@file_name, &:read)

        assert_equal @data_str, decrypted
      end

      it "decrypt from file a line at a time" do
        SymmetricEncryption::Reader.open(@file_name) do |file|
          i = 0
          file.each_line do |line|
            assert_equal @data[i], line
            i += 1
          end
        end
      end

      it "support rewind" do
        decrypted = SymmetricEncryption::Reader.open(@file_name) do |file|
          file.read
          file.rewind
          file.read
        end

        assert_equal @data_str, decrypted
      end
    end

    describe "reading from files with previous keys without a header" do
      before do
        @file_name = "_test"
        # Create encrypted file with old encryption key
        SymmetricEncryption::Writer.open(@file_name, version: 0, header: false, random_key: false, random_iv: false, compress: false) do |file|
          @data.inject(0) { |sum, str| sum + file.write(str) }
        end
      end

      after do
        FileUtils.rm_f(@file_name)
      rescue Errno::EACCES
        # Required for Windows
        nil
      end

      it "decrypt from file in a single read" do
        decrypted = SymmetricEncryption::Reader.open(@file_name, version: 0, &:read)

        assert_equal @data_str, decrypted
      end

      it "decrypt from file in a single read with different version" do
        # Should fail since file was encrypted using version 0 key
        assert_raises OpenSSL::Cipher::CipherError do
          SymmetricEncryption::Reader.read(@file_name, version: 1)
        end
      end
    end

    describe "stream methods" do
      before do
        @file_name = "tmp/reader_stream_test"
        FileUtils.makedirs("tmp")
        SymmetricEncryption::Writer.write(@file_name, @data_str, compress: false)
      end

      after do
        FileUtils.rm_f(@file_name)
      end

      it "#flush delegates to the stream" do
        SymmetricEncryption::Reader.open(@file_name) do |file|
          refute_nil file.flush
        end
      end

      it "#size returns the encrypted size" do
        SymmetricEncryption::Reader.open(@file_name) do |file|
          assert_equal File.size(@file_name), file.size
        end
      end

      it "#readline returns each line" do
        SymmetricEncryption::Reader.open(@file_name) do |file|
          assert_equal @data[0], file.readline
          assert_equal @data[1], file.readline
        end
      end

      it "#readline raises at the end of the file" do
        SymmetricEncryption::Reader.open(@file_name) do |file|
          file.read
          assert_raises(EOFError) { file.readline }
        end
      end

      it "#gets with a length" do
        SymmetricEncryption::Reader.open(@file_name) do |file|
          assert_equal @data_str[0, 5], file.gets(nil, 5)
        end
      end

      it "#seek to an absolute position" do
        SymmetricEncryption::Reader.open(@file_name) do |file|
          file.read(5)

          assert_equal 0, file.seek(10, IO::SEEK_SET)
          assert_equal @data_str[10..], file.read
        end
      end

      it "#seek forwards from the current position" do
        SymmetricEncryption::Reader.open(@file_name) do |file|
          file.read(5)
          file.seek(5, IO::SEEK_CUR)

          assert_equal @data_str[10..], file.read
        end
      end

      it "#seek backwards from the current position" do
        SymmetricEncryption::Reader.open(@file_name) do |file|
          file.read(15)
          file.seek(-5, IO::SEEK_CUR)

          assert_equal @data_str[10..], file.read
        end
      end

      it "#seek relative to the end of the file" do
        SymmetricEncryption::Reader.open(@file_name) do |file|
          file.seek(-10, IO::SEEK_END)

          assert_equal @data_str[-10..], file.read
        end
      end

      it "#seek raises for an unknown whence" do
        SymmetricEncryption::Reader.open(@file_name) do |file|
          assert_raises(ArgumentError) { file.seek(0, :bad_whence) }
        end
      end
    end

    # Whether the block form of `.open` closes the stream it was given is exactly what is under
    # test here, so these streams are deliberately opened without a block.
    # rubocop:disable Style/FileOpen
    describe "closing" do
      before do
        @file_name = "tmp/reader_close_test"
        FileUtils.makedirs("tmp")
      end

      after do
        FileUtils.rm_f(@file_name)
      end

      [true, false].each do |compress|
        describe "compress: #{compress}" do
          before do
            SymmetricEncryption::Writer.write(@file_name, @data_str, compress: compress)
          end

          it "closes the stream it was given" do
            stream = File.open(@file_name, "rb")
            SymmetricEncryption::Reader.open(stream, &:read)

            assert_predicate stream, :closed?
          end

          it "closes the file it opened" do
            reader = nil
            SymmetricEncryption::Reader.open(@file_name) { |file| reader = file }

            assert_predicate reader, :closed?
          end

          it "leaves the stream open without a block, it belongs to the caller" do
            stream = File.open(@file_name, "rb")
            reader = SymmetricEncryption::Reader.open(stream)

            refute_predicate stream, :closed?

            reader.close

            assert_predicate stream, :closed?
          end
        end
      end

      it "#closed? is public so that .open can close the reader" do
        assert SymmetricEncryption::Reader.public_method_defined?(:closed?)
      end

      it "#closed? follows the underlying stream" do
        SymmetricEncryption::Writer.write(@file_name, @data_str, compress: false)
        stream = File.open(@file_name, "rb")
        reader = SymmetricEncryption::Reader.new(stream)

        refute_predicate reader, :closed?

        stream.close

        assert_predicate reader, :closed?
      end
    end
    # rubocop:enable Style/FileOpen

    describe "data larger than the buffer size" do
      before do
        @file_name = "tmp/reader_large_test"
        FileUtils.makedirs("tmp")
        @large_data = "Hello World\n" * 5_000
        SymmetricEncryption::Writer.write(@file_name, @large_data, compress: false)
      end

      after do
        FileUtils.rm_f(@file_name)
      end

      it "reads across blocks" do
        assert_equal @large_data, SymmetricEncryption::Reader.read(@file_name)
      end

      it "reads a fixed length across blocks" do
        SymmetricEncryption::Reader.open(@file_name, buffer_size: 512) do |file|
          assert_equal @large_data[0, 4_096], file.read(4_096)
        end
      end

      it "reads line by line across blocks" do
        count = 0
        SymmetricEncryption::Reader.open(@file_name, buffer_size: 512) do |file|
          file.each_line { |_line| count += 1 }
        end

        assert_equal 5_000, count
      end
    end
  end
end
