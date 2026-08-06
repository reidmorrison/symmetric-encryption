require_relative "test_helper"
require "stringio"

# Unit Test for Symmetric::EncryptedStream
#
class WriterTest < Minitest::Test
  describe SymmetricEncryption::Writer do
    before do
      @data = [
        "Hello World\n",
        "Keep this secret\n",
        "And keep going even further and further..."
      ]
      @data_str = @data.inject("") { |sum, str| sum << str }
      @data_len = @data_str.length
      @file_name = "._test"
      @source_file_name = "._source_test"
    end

    after do
      FileUtils.rm_f(@file_name)
      FileUtils.rm_f(@source_file_name)
    end

    [true, false, nil].each do |compress|
      describe "compress: #{compress.inspect}" do
        describe ".open" do
          it "encrypt to stream" do
            written_len = 0
            stream      = StringIO.new
            SymmetricEncryption::Writer.open(stream, compress: compress) do |file|
              written_len = @data.inject(0) { |sum, str| sum + file.write(str) }
            end
            size = stream.string.size

            # Always larger than the plaintext: the header carries the key and iv, and with
            # small files the compressed file is larger too.
            assert_operator size, :>=, @data_len
            assert_equal @data_len, written_len
          end

          it "encrypt to file" do
            written_len = SymmetricEncryption::Writer.open(@file_name, compress: compress) do |file|
              @data.inject(0) { |sum, str| sum + file.write(str) }
            end

            assert_equal @data_len, written_len
            size = File.size(@file_name)

            # Always larger than the plaintext: the header carries the key and iv, and with
            # small files the compressed file is larger too.
            assert_operator size, :>=, @data_len

            assert_equal @data_str, SymmetricEncryption::Reader.read(@file_name)
          end
        end

        describe ".encrypt" do
          it "stream" do
            target_stream = StringIO.new
            source_stream = StringIO.new(@data_str)
            source_bytes  = SymmetricEncryption::Writer.encrypt(source: source_stream, target: target_stream, compress: compress)

            assert_equal @data_len, source_bytes
            assert_equal @data_str, SymmetricEncryption::Reader.read(StringIO.new(target_stream.string))
          end

          it "file" do
            File.binwrite(@source_file_name, @data_str)
            source_bytes = SymmetricEncryption::Writer.encrypt(source: @source_file_name, target: @file_name, compress: compress)

            assert_equal @data_len, source_bytes
            assert_equal @data_str, SymmetricEncryption::Reader.read(@file_name)
          end
        end
      end
    end

    describe "#initialize" do
      it "requires a random iv when using a random key" do
        error = assert_raises(ArgumentError) do
          SymmetricEncryption::Writer.new(StringIO.new, random_key: true, random_iv: false)
        end
        assert_includes error.message, ":random_iv must also be true"
      end

      it "only allows a cipher_name with a random key and iv" do
        error = assert_raises(ArgumentError) do
          SymmetricEncryption::Writer.new(StringIO.new, cipher_name: "aes-256-cbc", random_key: false, random_iv: false)
        end
        assert_includes error.message, "Cannot supply a :cipher_name"
      end

      it "raises when the version is not configured" do
        error = assert_raises(SymmetricEncryption::CipherError) do
          SymmetricEncryption::Writer.new(StringIO.new, version: 99)
        end
        assert_includes error.message, "not found"
      end
    end

    describe "#<<" do
      it "appends and returns self" do
        stream = StringIO.new
        writer = SymmetricEncryption::Writer.new(stream)

        assert_equal writer, writer << "Hello " << "World"
        writer.close(false)

        assert_equal "Hello World", SymmetricEncryption::Reader.read(StringIO.new(stream.string))
      end
    end

    describe "#write" do
      it "returns the number of bytes written" do
        stream = StringIO.new
        writer = SymmetricEncryption::Writer.new(stream)

        assert_equal 11, writer.write("Hello World")
        writer.close(false)
      end

      it "ignores nil" do
        stream = StringIO.new
        writer = SymmetricEncryption::Writer.new(stream)

        assert_nil writer.write(nil)
        assert_equal 0, writer.size
        writer.close(false)
      end

      it "converts non string values" do
        stream = StringIO.new
        writer = SymmetricEncryption::Writer.new(stream)
        writer.write(21)
        writer.close(false)

        assert_equal "21", SymmetricEncryption::Reader.read(StringIO.new(stream.string))
      end
    end

    describe "#flush" do
      it "delegates to the stream" do
        stream = StringIO.new
        writer = SymmetricEncryption::Writer.new(stream)

        refute_nil writer.flush
        writer.close(false)
      end
    end

    describe "#closed?" do
      it "is closed after close" do
        writer = SymmetricEncryption::Writer.new(StringIO.new)

        refute_predicate writer, :closed?

        writer.close(false)

        assert_predicate writer, :closed?
      end

      it "close is idempotent" do
        writer = SymmetricEncryption::Writer.new(StringIO.new)
        writer.write("Hello World")
        writer.close(false)

        writer.close(false)

        assert_predicate writer, :closed?
      end
    end
  end
end
