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
      @data_encrypted_without_header = SymmetricEncryption.cipher.binary_encrypt(@data_str)

      @data_encrypted_with_header = SymmetricEncryption::Cipher.magic_header(
        SymmetricEncryption.cipher.version,
        compress = false,
        SymmetricEncryption.cipher.send(:iv),
        SymmetricEncryption.cipher.send(:key),
        SymmetricEncryption.cipher.cipher_name)
      @data_encrypted_with_header << SymmetricEncryption.cipher.binary_encrypt(@data_str)

      # Verify regular decrypt can decrypt this string
      SymmetricEncryption.cipher.binary_decrypt(@data_encrypted_without_header)
      SymmetricEncryption.cipher.binary_decrypt(@data_encrypted_with_header)
    end

    [true, false].each do |header|
      context header do
        setup do
          @data_encrypted = header ? @data_encrypted_with_header : @data_encrypted_without_header
        end

        should "decrypt from string stream as a single read" do
          stream = StringIO.new(@data_encrypted)
          decrypted = SymmetricEncryption::Reader.open(stream) {|file| file.read}
          assert_equal @data_str, decrypted
        end

        should "decrypt from string stream as a single read, after a partial read" do
          stream = StringIO.new(@data_encrypted)
          decrypted = SymmetricEncryption::Reader.open(stream) do |file|
            file.read(10)
            file.read
          end
          assert_equal @data_str[10..-1], decrypted
        end

        should "decrypt lines from string stream" do
          stream = StringIO.new(@data_encrypted)
          i = 0
          decrypted = SymmetricEncryption::Reader.open(stream) do |file|
            file.each_line do |line|
              assert_equal @data[i], line
              i += 1
            end
          end
        end

        should "decrypt fixed lengths from string stream" do
          stream = StringIO.new(@data_encrypted)
          i = 0
          SymmetricEncryption::Reader.open(stream) do |file|
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

    context "reading from file" do
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
        context "with options: #{options.inspect}" do
          setup do
            @filename = '._test'
            @empty_encrypted_filename = '._test_empty'
            @empty_filename = File.join(File.dirname(__FILE__), 'config/empty.csv')
            # Create encrypted file
            SymmetricEncryption::Writer.open(@filename, options) do |file|
              @data.inject(0) {|sum,str| sum + file.write(str)}
            end
            SymmetricEncryption::Writer.open(@empty_encrypted_filename, options) do |file|
              # Leave data portion empty
            end
          end

          teardown do
            File.delete(@filename) if File.exist?(@filename)
            File.delete(@empty_encrypted_filename) if File.exist?(@empty_encrypted_filename)
          end

          should "decrypt from file in a single read" do
            assert_equal @data_str, SymmetricEncryption::Reader.open(@filename) {|file| file.read}
          end

          should "decrypt from empty file" do
            assert_equal '', SymmetricEncryption::Reader.open(@empty_filename, :version => 0) {|file| file.read}
          end

          should "decrypt from empty file using read(size)" do
            ios = SymmetricEncryption::Reader.open(@empty_filename, :version => 0)
            assert_equal nil, ios.read(4096)
          end

          should "check if file is empty" do
            assert_equal false, SymmetricEncryption::Reader.empty?(@filename)
            assert_equal true, SymmetricEncryption::Reader.empty?(@empty_encrypted_filename)
            assert_equal true, SymmetricEncryption::Reader.empty?(@empty_filename)
            assert_raise Errno::ENOENT do
              assert_equal false, SymmetricEncryption::Reader.empty?('missing_file')
            end
          end

          # File with encryption header but no data
          should "decrypt from empty encrypted file" do
            if options[:header] == false
              assert_equal 0, File.size(@empty_encrypted_filename)
            end
            assert_equal '', SymmetricEncryption::Reader.open(@empty_encrypted_filename, :version => 0) {|file| file.read}
          end

          should "decrypt from empty encrypted file using read(size)" do
            if options[:header] == false
              assert_equal 0, File.size(@empty_encrypted_filename)
            end
            ios = SymmetricEncryption::Reader.open(@empty_encrypted_filename, :version => 0)
            assert_equal nil, ios.read(4096)
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
      end

    end

    context "reading from files with previous keys" do
      setup do
        @filename = '._test'
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
        @filename = '._test'
        # Create encrypted file with old encryption key
        SymmetricEncryption::Writer.open(@filename, :version => 0, :header => false, :random_key => false) do |file|
          @data.inject(0) {|sum,str| sum + file.write(str)}
        end
      end

      teardown do
        File.delete(@filename) if File.exist?(@filename)
      end

      should "decrypt from file in a single read" do
        decrypted = SymmetricEncryption::Reader.open(@filename, :version => 0) {|file| file.read}
        assert_equal @data_str, decrypted
      end

      should "decrypt from file in a single read with different version" do
        # Should fail since file was encrypted using version 0 key
        assert_raise OpenSSL::Cipher::CipherError do
          SymmetricEncryption::Reader.open(@filename, :version => 1) {|file| file.read}
        end
      end
    end

  end
end
