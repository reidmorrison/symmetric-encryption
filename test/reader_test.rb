# Allow examples to be run in-place without requiring a gem install
$LOAD_PATH.unshift File.dirname(__FILE__) + '/../lib'

require 'stringio'
require 'rubygems'
require 'test/unit'
require 'shoulda'
require 'symmetric-encryption'

# Load Symmetric Encryption keys
SymmetricEncryption.load!(File.join(File.dirname(__FILE__), 'config', 'symmetric-encryption.yml'), 'test')

# Unit Test for SymmetricEncrypted::ReaderStream
#
class ReaderTest < Test::Unit::TestCase
  context SymmetricEncryption::Reader do
    setup do
      @data = [
        "Hello World\n",
        "Keep this secret\n",
        "And keep going even further and further..."
      ]
      @data_str = @data.inject('') {|sum,str| sum << str}
      @data_len = @data_str.length
      # Use Cipher 0 since it does not always include a header
      @cipher = SymmetricEncryption.cipher(0)
      @data_encrypted_without_header = @cipher.binary_encrypt(@data_str)

      @data_encrypted_with_header = SymmetricEncryption::Cipher.build_header(
        @cipher.version,
        compress = false,
        @cipher.send(:iv),
        @cipher.send(:key),
        @cipher.cipher_name
      )
      @data_encrypted_with_header << @cipher.binary_encrypt(@data_str)

      # Verify regular decrypt can decrypt this string
      @cipher.binary_decrypt(@data_encrypted_without_header)
      @cipher.binary_decrypt(@data_encrypted_with_header)
      assert @data_encrypted_without_header != @data_encrypted_with_header
    end

    [true, false].each do |header|
      context header do
        setup do
          @data_encrypted = header ? @data_encrypted_with_header : @data_encrypted_without_header
        end

        should "#read()" do
          stream = StringIO.new(@data_encrypted)
          # Version 0 supplied if the file/stream does not have a header
          decrypted = SymmetricEncryption::Reader.open(stream, version: 0) {|file| file.read}
          assert_equal @data_str, decrypted
        end

        should "#read(size) followed by #read()" do
          stream = StringIO.new(@data_encrypted)
          # Version 0 supplied if the file/stream does not have a header
          decrypted = SymmetricEncryption::Reader.open(stream, version: 0) do |file|
            file.read(10)
            file.read
          end
          assert_equal @data_str[10..-1], decrypted
        end

        should "#each_line" do
          stream = StringIO.new(@data_encrypted)
          i = 0
          # Version 0 supplied if the file/stream does not have a header
          decrypted = SymmetricEncryption::Reader.open(stream, version: 0) do |file|
            file.each_line do |line|
              assert_equal @data[i], line
              i += 1
            end
          end
        end

        should "#read(size)" do
          stream = StringIO.new(@data_encrypted)
          i = 0
          # Version 0 supplied if the file/stream does not have a header
          decrypted = SymmetricEncryption::Reader.open(stream, version: 0) do |file|
            index = 0
            [0,10,5,5000].each do |size|
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
      {:header => false, :random_key => false, :random_iv => false},
      # Default Header with random key and iv
      {},
      # Header with no compression ( default anyway )
      {:compress => false},
      # Compress and use Random key, iv
      {:compress => true},
      # Header but not random key or iv
      {:random_key => false},
      # Random iv only
      {:random_key => false, :random_iv => true},
      # Random iv only with compression
      {:random_iv => true, :compress => true},
    ].each do |options|

      [:data, :empty, :blank].each do |usecase|

        context "read from #{usecase} file with options: #{options.inspect}" do
          setup do
            case usecase
            when :data
              # Create encrypted file
              @eof = false
              @filename = '_test'
              @header = (options[:header] != false)
              SymmetricEncryption::Writer.open(@filename, options) do |file|
                @data.inject(0) {|sum,str| sum + file.write(str)}
              end
            when :empty
              @data_str = ''
              @eof = true
              @filename = '_test_empty'
              @header = (options[:header] != false)
              SymmetricEncryption::Writer.open(@filename, options) do |file|
                # Leave data portion empty
              end
            when :blank
              @data_str = ''
              @eof = true
              @filename = File.join(File.dirname(__FILE__), 'config/empty.csv')
              @header = false
              assert_equal 0, File.size(@filename)
            else
              raise "Unhandled usecase: #{usecase}"
            end
            @data_size = @data_str.length
          end

          teardown do
            File.delete(@filename) if File.exist?(@filename) && !@filename.end_with?('empty.csv')
          end

          should ".empty?" do
            assert_equal (@data_size==0), SymmetricEncryption::Reader.empty?(@filename)
            assert_raise Errno::ENOENT do
              SymmetricEncryption::Reader.empty?('missing_file')
            end
          end

          should ".header_present?" do
            assert_equal @header, SymmetricEncryption::Reader.header_present?(@filename)
            assert_raise Errno::ENOENT do
              SymmetricEncryption::Reader.header_present?('missing_file')
            end
          end

          should ".open return Zlib::GzipReader when compressed" do
            file = SymmetricEncryption::Reader.open(@filename)
            #assert_equal (@header && (options[:compress]||false)), file.is_a?(Zlib::GzipReader)
            file.close
          end

          should "#read()" do
            data = nil
            eof = nil
            result = SymmetricEncryption::Reader.open(@filename) do |file|
              eof = file.eof?
              data = file.read
            end
            assert_equal @eof, eof
            assert_equal @data_str, data
            assert_equal @data_str, result
          end

          should "#read(size)" do
            data = nil
            eof = nil
            file = SymmetricEncryption::Reader.open(@filename)
            eof = file.eof?
            data = file.read(4096)
            file.close

            assert_equal @eof, eof
            assert_equal (@data_size > 0 ? @data_str : nil), data
          end

          should "#each_line" do
            decrypted = SymmetricEncryption::Reader.open(@filename) do |file|
              i = 0
              file.each_line do |line|
                assert_equal @data[i], line
                i += 1
              end
            end
          end

          should "#rewind" do
            decrypted = SymmetricEncryption::Reader.open(@filename) do |file|
              file.read
              file.rewind
              file.read
            end
            assert_equal @data_str, decrypted
          end

          should "#gets(nil,size)" do
            data = nil
            eof = nil
            file = SymmetricEncryption::Reader.open(@filename)
            eof = file.eof?
            data = file.gets(nil,4096)
            file.close

            assert_equal @eof, eof
            assert_equal (@data_size > 0 ? @data_str : nil), data
          end

          should "#gets(delim)" do
            decrypted = SymmetricEncryption::Reader.open(@filename) do |file|
              i = 0
              while line = file.gets("\n")
                assert_equal @data[i], line
                i += 1
              end
              assert_equal (@data_size > 0 ? 3 : 0), i
            end
          end

          should "#gets(delim,size)" do
            decrypted = SymmetricEncryption::Reader.open(@filename) do |file|
              i = 0
              while line = file.gets("\n",128)
                i += 1
              end
              assert_equal (@data_size > 0 ? 3 : 0), i
            end
          end

        end
      end
    end

    context "reading from files with previous keys" do
      setup do
        @filename = '_test'
        # Create encrypted file with old encryption key
        SymmetricEncryption::Writer.open(@filename, :version => 0) do |file|
          @data.inject(0) {|sum,str| sum + file.write(str)}
        end
      end

      teardown do
        File.delete(@filename) if File.exist?(@filename)
      end

      should "decrypt from file in a single read" do
        decrypted = SymmetricEncryption::Reader.open(@filename) {|file| file.read}
        assert_equal @data_str, decrypted
      end

      should "decrypt from file a line at a time" do
        decrypted = SymmetricEncryption::Reader.open(@filename) do |file|
          i = 0
          file.each_line do |line|
            assert_equal @data[i], line
            i += 1
          end
        end
      end

      should "support rewind" do
        decrypted = SymmetricEncryption::Reader.open(@filename) do |file|
          file.read
          file.rewind
          file.read
        end
        assert_equal @data_str, decrypted
      end
    end

    context "reading from files with previous keys without a header" do
      setup do
        @filename = '_test'
        # Create encrypted file with old encryption key
        SymmetricEncryption::Writer.open(@filename, :version => 0, :header => false, :random_key => false) do |file|
          @data.inject(0) {|sum,str| sum + file.write(str)}
        end
      end

      teardown do
        begin
          File.delete(@filename) if File.exist?(@filename)
        rescue Errno::EACCES
          # Required for Windows
        end
      end

      should "decrypt from file in a single read" do
        decrypted = SymmetricEncryption::Reader.open(@filename, :version => 0) {|file| file.read}
        assert_equal @data_str, decrypted
      end

      should "decrypt from file in a single read with different version" do
        # Should fail since file was encrypted using version 0 key
        assert_raise OpenSSL::Cipher::CipherError do
          SymmetricEncryption::Reader.open(@filename, :version => 2) {|file| file.read}
        end
      end
    end

  end
end
