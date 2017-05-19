require_relative 'test_helper'
require 'stringio'

# Unit Test for Symmetric::EncryptedStream
#
class WriterTest < Minitest::Test
  describe SymmetricEncryption::Writer do
    before do
      @data            = [
        "Hello World\n",
        "Keep this secret\n",
        'And keep going even further and further...'
      ]
      @data_str        = @data.inject('') { |sum, str| sum << str }
      @data_len        = @data_str.length
      @data_encrypted  = SymmetricEncryption.cipher.binary_encrypt(@data_str, false, false, false)
      @filename        = '._test'
      @source_filename = '._source_test'
    end

    after do
      File.delete(@filename) if File.exist?(@filename)
      File.delete(@source_filename) if File.exist?(@source_filename)
    end

    describe '#write' do
      it 'encrypt to string stream' do
        stream      = StringIO.new
        file        = SymmetricEncryption::Writer.new(stream, header: false, random_key: false, random_iv: false)
        written_len = @data.inject(0) { |sum, str| sum + file.write(str) }
        assert_equal @data_len, file.size
        file.close

        assert_equal @data_len, written_len
        result = stream.string
        result.force_encoding('binary') if defined?(Encoding)
        assert_equal @data_encrypted, result
      end
    end

    describe '.open' do
      it 'encrypt to stream' do
        written_len = 0
        stream      = StringIO.new
        SymmetricEncryption::Writer.open(stream) do |file|
          written_len = @data.inject(0) { |sum, str| sum + file.write(str) }
          assert_equal @data_len, file.size
        end
        assert_equal @data_len, written_len
      end

      it 'encrypt to file' do
        written_len = nil
        SymmetricEncryption::Writer.open(@filename, header: false, random_key: false, random_iv: false) do |file|
          written_len = @data.inject(0) { |sum, str| sum + file.write(str) }
          assert_equal @data_len, file.size
        end
        assert_equal @data_len, written_len
        assert_equal @data_encrypted, File.read(@filename, mode: 'rb')
      end
    end

    describe '.encrypt' do
      it 'stream' do
        target_stream = StringIO.new
        source_stream = StringIO.new(@data)
        source_bytes  = SymmetricEncryption::Writer.encrypt(source: source_stream, target: target_stream)
        assert_equal @data_len, source_bytes
        assert_equal @data_encrypted, target_stream.string
      end

      it 'file' do
        File.write(@source_filename, 'wb') { |f| f.write(@data) }
        source_bytes = SymmetricEncryption::Writer.encrypt(source: @source_filename, target: @filename)
        assert_equal @data_len, source_bytes
        assert_equal @data_encrypted, File.read(@filename, mode: 'rb')
      end
    end

  end
end
