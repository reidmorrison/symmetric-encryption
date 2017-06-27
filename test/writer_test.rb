require_relative 'test_helper'
require 'stringio'

# Unit Test for Symmetric::EncryptedStream
#
class WriterTest < Minitest::Test
  describe SymmetricEncryption::Writer do
    before do
      @data             = [
        "Hello World\n",
        "Keep this secret\n",
        'And keep going even further and further...'
      ]
      @data_str         = @data.inject('') { |sum, str| sum << str }
      @data_len         = @data_str.length
      @file_name        = '._test'
      @source_file_name = '._source_test'
    end

    after do
      File.delete(@file_name) if File.exist?(@file_name)
      File.delete(@source_file_name) if File.exist?(@source_file_name)
    end

    describe '#write' do
      it 'encrypt to string stream' do
        stream      = StringIO.new
        file        = SymmetricEncryption::Writer.new(stream)
        written_len = @data.inject(0) { |sum, str| sum + file.write(str) }
        assert_equal @data_len, file.size
        file.close

        assert_equal @data_len, written_len
        assert_equal @data_str, SymmetricEncryption::Reader.read(StringIO.new(stream.string))
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
        SymmetricEncryption::Writer.open(@file_name) do |file|
          written_len = @data.inject(0) { |sum, str| sum + file.write(str) }
          assert_equal @data_len, file.size
        end
        assert_equal @data_len, written_len
        assert_equal @data_str, SymmetricEncryption::Reader.read(@file_name)
      end
    end

    describe '.encrypt' do
      it 'stream' do
        target_stream = StringIO.new
        source_stream = StringIO.new(@data_str)
        source_bytes  = SymmetricEncryption::Writer.encrypt(source: source_stream, target: target_stream)
        assert_equal @data_len, source_bytes
        assert_equal @data_str, SymmetricEncryption::Reader.read(StringIO.new(target_stream.string))
      end

      it 'file' do
        File.open(@source_file_name, 'wb') { |f| f.write(@data_str) }
        source_bytes = SymmetricEncryption::Writer.encrypt(source: @source_file_name, target: @file_name)
        assert_equal @data_len, source_bytes
        assert_equal @data_str, SymmetricEncryption::Reader.read(@file_name)
      end
    end

  end
end
