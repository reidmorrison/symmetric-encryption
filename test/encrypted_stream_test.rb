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
class EncryptedStreamTest < Test::Unit::TestCase
  context 'file tests' do
    setup do
      @data = [
        "Hello World\n",
        "Keep this secret\n",
        "And keep going even further and further..."
      ]
      @data_str = @data.inject('') {|sum,str| sum << str}
      @data_len = @data_str.length
      @filename = '._test'
    end

    should "encrypt to string stream" do
      stream = StringIO.new
      file = Symmetric::EncryptedStream.new(stream)
      written_len = @data.inject(0) {|sum,str| sum + file.write(str)}
      file.close

      assert_equal @data_len, written_len
    end

    should "encrypt to string stream using .stream" do
      stream = StringIO.new
      Symmetric::EncryptedStream.stream(stream) do |file|
        written_len = @data.inject(0) {|sum,str| sum + file.write(str)}
        assert_equal @data_len, written_len
      end
    end

    should "encrypt to file" do
      written_len = nil
      Symmetric::EncryptedStream.open(@filename, 'w') do |file|
        written_len = @data.inject(0) {|sum,str| sum + file.write(str)}
      end
      assert_equal @data_len, written_len
    end

    should "decrypt from string stream as a single read" do
      stream = StringIO.new
      written_len = nil
      Symmetric::EncryptedStream.stream(stream) do |file|
        written_len = @data.inject(0) {|sum,str| sum + file.write(str)}
      end
      assert_equal @data_len, written_len

      # Now decrypt the data
      stream2 = StringIO.new(stream.string)
      decrypted = Symmetric::EncryptedStream.stream(stream2) {|file| file.read}
      assert_equal @data_str, decrypted
    end

    should "decrypt lines from string stream" do
      stream = StringIO.new
      written_len = nil
      Symmetric::EncryptedStream.stream(stream) do |file|
        written_len = @data.inject(0) {|sum,str| sum + file.write(str)}
      end
      assert_equal @data_len, written_len

      # Now decrypt the data
      stream2 = StringIO.new(stream.string)
      i = 0
      decrypted = Symmetric::EncryptedStream.stream(stream2) do |file|
        file.each_line do |line|
          assert_equal @data[i], line
          i += 1
        end
      end
    end

    should "decrypt fixed lengths from string stream" do
      stream = StringIO.new
      written_len = nil
      Symmetric::EncryptedStream.stream(stream) do |file|
        written_len = @data.inject(0) {|sum,str| sum + file.write(str)}
      end
      assert_equal @data_len, written_len

      # Now decrypt the data
      stream2 = StringIO.new(stream.string)
      i = 0
      decrypted = Symmetric::EncryptedStream.stream(stream2) do |file|
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
