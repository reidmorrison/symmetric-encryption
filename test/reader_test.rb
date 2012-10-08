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
  context 'Reader' do
    setup do
      @data = [
        "Hello World\n",
        "Keep this secret\n",
        "And keep going even further and further..."
      ]
      @data_str = @data.inject('') {|sum,str| sum << str}
      @data_len = @data_str.length
      @data_encrypted = SymmetricEncryption.cipher.encrypt(@data_str)
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

    context "reading from file" do
      # With and without header
      [{:header => false}, {:compress => false}, {:compress => true}].each_with_index do |options, i|
        context "with#{'out' unless options[:header]} header #{i}" do
          setup do
            @filename = '._test'
            # Create encrypted file
            SymmetricEncryption::Writer.open(@filename, options) do |file|
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
      end

    end
  end
end