# Allow examples to be run in-place without requiring a gem install
$LOAD_PATH.unshift File.dirname(__FILE__) + '/../lib'

require 'stringio'
require 'rubygems'
require 'test/unit'
require 'shoulda'
require 'symmetric-encryption'

# Load Symmetric Encryption keys
SymmetricEncryption.load!(File.join(File.dirname(__FILE__), 'config', 'symmetric-encryption.yml'), 'test')

# Unit Test for Symmetric::EncryptedStream
#
class WriterTest < Test::Unit::TestCase
  context SymmetricEncryption::Writer do
    setup do
      @data = [
        "Hello World\n",
        "Keep this secret\n",
        "And keep going even further and further..."
      ]
      @data_str = @data.inject('') {|sum,str| sum << str}
      @data_len = @data_str.length
      cipher = SymmetricEncryption.cipher
      before = cipher.always_add_header
      cipher.always_add_header = false
      @data_encrypted = SymmetricEncryption.cipher.binary_encrypt(@data_str, false, false)
      cipher.always_add_header = before
      @filename = '._test'
    end

    teardown do
      File.delete(@filename) if File.exist?(@filename)
    end

    should "encrypt to string stream" do
      stream = StringIO.new
      file = SymmetricEncryption::Writer.new(stream, :header => false, :random_key => false, :random_iv => false)
      written_len = @data.inject(0) {|sum,str| sum + file.write(str)}
      assert_equal @data_len, file.size
      file.close

      assert_equal @data_len, written_len
      result = stream.string
      result.force_encoding('binary') if defined?(Encoding)
      assert_equal @data_encrypted, result
    end

    should "encrypt to string stream using .open" do
      written_len = 0
      stream = StringIO.new
      SymmetricEncryption::Writer.open(stream) do |file|
        written_len = @data.inject(0) {|sum,str| sum + file.write(str)}
        assert_equal @data_len, file.size
      end
      assert_equal @data_len, written_len
    end

    should "encrypt to file using .open" do
      written_len = nil
      SymmetricEncryption::Writer.open(@filename, :header => false, :random_key => false, :random_iv => false) do |file|
        written_len = @data.inject(0) {|sum,str| sum + file.write(str)}
        assert_equal @data_len, file.size
      end
      assert_equal @data_len, written_len
      assert_equal @data_encrypted, File.open(@filename, 'rb') {|f| f.read }
    end
  end
end
