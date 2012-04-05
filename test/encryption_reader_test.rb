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
class EncryptionReaderTest < Test::Unit::TestCase
  context 'EncryptionReader' do
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

    should "decrypt from string stream as a single read" do
      stream = StringIO.new(@data_encrypted)
      decrypted = Symmetric::EncryptionReader.open(stream) {|file| file.read}
      assert_equal @data_str, decrypted
    end

    should "decrypt from string stream as a single read, after a partial read" do
      stream = StringIO.new(@data_encrypted)
      decrypted = Symmetric::EncryptionReader.open(stream) do |file|
        file.read(10)
        file.read
      end
      assert_equal @data_str[10..-1], decrypted
    end

    should "decrypt lines from string stream" do
      stream = StringIO.new(@data_encrypted)
      i = 0
      decrypted = Symmetric::EncryptionReader.open(stream) do |file|
        file.each_line do |line|
          assert_equal @data[i], line
          i += 1
        end
      end
    end

    should "decrypt fixed lengths from string stream" do
      stream = StringIO.new(@data_encrypted)
      i = 0
      Symmetric::EncryptionReader.open(stream) do |file|
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

    should "decrypt from file" do

    end
  end

end
