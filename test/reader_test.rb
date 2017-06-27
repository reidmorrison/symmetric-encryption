require_relative 'test_helper'
require 'stringio'

# Unit Test for SymmetricEncrypted::ReaderStream
#
class ReaderTest < Minitest::Test
  describe SymmetricEncryption::Reader do
    before do
      @data     = [
        "Hello World\n",
        "Keep this secret\n",
        'And keep going even further and further...'
      ]
      @data_str = @data.inject('') { |sum, str| sum << str }
      @data_len = @data_str.length
      # Use Cipher 0 since it does not always include a header
      @cipher                        = SymmetricEncryption.cipher(0)
      @data_encrypted_without_header = @cipher.binary_encrypt(@data_str, header: false)

      header                      = SymmetricEncryption::Header.new(
        version:     @cipher.version,
        iv:          @cipher.iv,
        key:         @cipher.send(:key),
        cipher_name: @cipher.cipher_name
      )
      @data_encrypted_with_header = @cipher.binary_encrypt(@data_str, header: header)

      # Verify regular decrypt can decrypt this string
      @cipher.binary_decrypt(@data_encrypted_without_header)
      @cipher.binary_decrypt(@data_encrypted_with_header)
      assert @data_encrypted_without_header != @data_encrypted_with_header
    end

    [true, false].each do |header|
      describe header do
        before do
          @data_encrypted = header ? @data_encrypted_with_header : @data_encrypted_without_header
        end

        it "#read()" do
          stream = StringIO.new(@data_encrypted)
          # Version 0 supplied if the file/stream does not have a header
          decrypted = SymmetricEncryption::Reader.open(stream, version: 0) { |file| file.read }
          assert_equal @data_str, decrypted
        end

        it "#read(size) followed by #read()" do
          stream = StringIO.new(@data_encrypted)
          # Version 0 supplied if the file/stream does not have a header
          decrypted = SymmetricEncryption::Reader.open(stream, version: 0) do |file|
            file.read(10)
            file.read
          end
          assert_equal @data_str[10..-1], decrypted
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
              if size == 0
                assert_equal '', buf
              else
                assert_equal @data_str[index..index+size-1], buf
              end
              index += size
            end
          end
        end
      end
    end

    [
      # No Header
      {header: false, random_key: false, random_iv: false},
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
      {random_iv: true, compress: true},
    ].each do |options|

      [:data, :empty, :blank].each do |usecase|

        describe "read from #{usecase} file with options: #{options.inspect}" do
          before do
            case usecase
            when :data
              # Create encrypted file
              @eof       = false
              @file_name = '_test'
              @header    = (options[:header] != false)
              SymmetricEncryption::Writer.open(@file_name, options) do |file|
                @data.inject(0) { |sum, str| sum + file.write(str) }
              end
            when :empty
              @data_str  = ''
              @eof       = true
              @file_name = '_test_empty'
              @header    = (options[:header] != false)
              SymmetricEncryption::Writer.open(@file_name, options) do |file|
                # Leave data portion empty
              end
            when :blank
              @data_str  = ''
              @eof       = true
              @file_name = File.join(File.dirname(__FILE__), 'config/empty.csv')
              @header    = false
              assert_equal 0, File.size(@file_name)
            else
              raise "Unhandled usecase: #{usecase}"
            end
            @data_size = @data_str.length
          end

          after do
            File.delete(@file_name) if File.exist?(@file_name) && !@file_name.end_with?('empty.csv')
          end

          it '.empty?' do
            assert_equal (@data_size==0), SymmetricEncryption::Reader.empty?(@file_name)
            assert_raises Errno::ENOENT do
              SymmetricEncryption::Reader.empty?('missing_file')
            end
          end

          it '.header_present?' do
            assert_equal @header, SymmetricEncryption::Reader.header_present?(@file_name)
            assert_raises Errno::ENOENT do
              SymmetricEncryption::Reader.header_present?('missing_file')
            end
          end

          it '.open return Zlib::GzipReader when compressed' do
            file = SymmetricEncryption::Reader.open(@file_name)
            #assert_equal (@header && (options[:compress]||false)), file.is_a?(Zlib::GzipReader)
            file.close
          end

          it '#read' do
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

          it '#read(size)' do
            file = SymmetricEncryption::Reader.open(@file_name)
            eof  = file.eof?
            data = file.read(4096)
            file.close

            assert_equal @eof, eof
            if @data_size > 0
              assert_equal @data_str, data
            else
              assert_nil data
            end

          end

          it '#each_line' do
            SymmetricEncryption::Reader.open(@file_name) do |file|
              i = 0
              file.each_line do |line|
                assert_equal @data[i], line
                i += 1
              end
            end
          end

          it '#rewind' do
            decrypted = SymmetricEncryption::Reader.open(@file_name) do |file|
              file.read
              file.rewind
              file.read
            end
            assert_equal @data_str, decrypted
          end

          it '#gets(nil,size)' do
            file = SymmetricEncryption::Reader.open(@file_name)
            eof  = file.eof?
            data = file.gets(nil, 4096)
            file.close

            assert_equal @eof, eof
            if @data_size > 0
              assert_equal @data_str, data
            else
              # On JRuby Zlib::GzipReader.new(file) returns '' instead of nil
              # on an empty file
              if defined?(JRuby) && options[:compress] && (usecase == :empty)
                assert_equal '', data
              else
                assert_nil data
              end
            end
          end

          it '#gets(delim)' do
            SymmetricEncryption::Reader.open(@file_name) do |file|
              i = 0
              while line = file.gets("\n")
                assert_equal @data[i], line
                i += 1
              end
              assert_equal (@data_size > 0 ? 3 : 0), i
            end
          end

          it '#gets(delim,size)' do
            SymmetricEncryption::Reader.open(@file_name) do |file|
              i = 0
              while file.gets("\n", 128)
                i += 1
              end
              assert_equal (@data_size > 0 ? 3 : 0), i
            end
          end

        end
      end
    end

    describe 'reading from files with previous keys' do
      before do
        @file_name = '_test'
        # Create encrypted file with old encryption key
        SymmetricEncryption::Writer.open(@file_name, version: 0) do |file|
          @data.inject(0) { |sum, str| sum + file.write(str) }
        end
      end

      after do
        File.delete(@file_name) if File.exist?(@file_name)
      end

      it 'decrypt from file in a single read' do
        decrypted = SymmetricEncryption::Reader.open(@file_name) { |file| file.read }
        assert_equal @data_str, decrypted
      end

      it 'decrypt from file a line at a time' do
        SymmetricEncryption::Reader.open(@file_name) do |file|
          i = 0
          file.each_line do |line|
            assert_equal @data[i], line
            i += 1
          end
        end
      end

      it 'support rewind' do
        decrypted = SymmetricEncryption::Reader.open(@file_name) do |file|
          file.read
          file.rewind
          file.read
        end
        assert_equal @data_str, decrypted
      end
    end

    describe 'reading from files with previous keys without a header' do
      before do
        @file_name = '_test'
        # Create encrypted file with old encryption key
        SymmetricEncryption::Writer.open(@file_name, version: 0, header: false, random_key: false, random_iv: false) do |file|
          @data.inject(0) { |sum, str| sum + file.write(str) }
        end
      end

      after do
        begin
          File.delete(@file_name) if File.exist?(@file_name)
        rescue Errno::EACCES
          # Required for Windows
        end
      end

      it 'decrypt from file in a single read' do
        decrypted = SymmetricEncryption::Reader.open(@file_name, version: 0) { |file| file.read }
        assert_equal @data_str, decrypted
      end

      it 'decrypt from file in a single read with different version' do
        # Should fail since file was encrypted using version 0 key
        assert_raises OpenSSL::Cipher::CipherError do
          SymmetricEncryption::Reader.read(@file_name, version: 1)
        end
      end
    end

  end
end
