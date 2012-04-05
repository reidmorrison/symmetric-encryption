# Allow examples to be run in-place without requiring a gem install
$LOAD_PATH.unshift File.dirname(__FILE__) + '/../lib'

require 'rubygems'
require 'test/unit'
require 'shoulda'
require 'symmetric-encryption'

# Use test keys
Symmetric::Encryption.cipher = Symmetric::Cipher.new(:key => '1234567890ABCDEF1234567890ABCDEF', :iv=> '1234567890ABCDEF')

# Unit Test for Symmetric::EncryptedStream
#
class EncryptionWriterTest < Test::Unit::TestCase
  context 'EncryptionWriter' do
    setup do
      @data = [
        "Hello World\n",
        "Keep this secret\n",
        "And keep going even further and further..."
      ]
      @data_str = @data.inject('') {|sum,str| sum << str}
      @data_len = @data_str.length
      @data_encrypted = Symmetric::Encryption.cipher.encrypt(@data_str)
      @filename = '._test'
    end

    should "encrypt to string stream" do
      stream = StringIO.new
      file = Symmetric::EncryptionWriter.new(stream)
      written_len = @data.inject(0) {|sum,str| sum + file.write(str)}
      file.close

      assert_equal @data_len, written_len
      assert_equal @data_encrypted, stream.string
    end

    should "encrypt to string stream using .open" do
      written_len = 0
      stream = StringIO.new
      Symmetric::EncryptionWriter.open(stream) do |file|
        written_len = @data.inject(0) {|sum,str| sum + file.write(str)}
      end
      assert_equal @data_len, written_len
    end

    should "encrypt to file using .open" do
      written_len = nil
      Symmetric::EncryptionWriter.open(@filename) do |file|
        written_len = @data.inject(0) {|sum,str| sum + file.write(str)}
      end
      assert_equal @data_len, written_len
      assert_equal @data_encrypted, File.read(@filename)
    end
  end
end
