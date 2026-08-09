require_relative "test_helper"

# A stream encrypted with an authenticated cipher is split into chunks, each with its own auth
# tag, so that it can be verified as it is read rather than only once all of it has been read.
class ChunkedStreamTest < Minitest::Test
  describe SymmetricEncryption::ChunkedStream do
    # Small, so that the tests cross chunk boundaries without moving megabytes around.
    let :the_chunk_size do
      1024
    end

    let :the_cipher do
      SymmetricEncryption::Cipher.new(
        key: "12345678901234567890123456789012", cipher_name: "aes-256-gcm", version: 3
      )
    end

    let :the_file_name do
      "._chunked_test"
    end

    # More than one chunk, so that the stream is chunked rather than written as a single value.
    let :the_data do
      OpenSSL::Random.random_bytes((the_chunk_size * 3) + 500)
    end

    before do
      @original_cipher            = SymmetricEncryption.cipher
      @original_secondary_ciphers = SymmetricEncryption.secondary_ciphers
      SymmetricEncryption.cipher            = the_cipher
      SymmetricEncryption.secondary_ciphers = []
    end

    after do
      SymmetricEncryption.cipher            = @original_cipher
      SymmetricEncryption.secondary_ciphers = @original_secondary_ciphers
      FileUtils.rm_f(the_file_name)
    end

    def write(data, **args)
      SymmetricEncryption::Writer.open(the_file_name, compress: false, chunk_size: 1024, **args) do |file|
        file.write(data)
      end
    end

    def parsed_header
      header = SymmetricEncryption::Header.new
      header.parse(File.binread(the_file_name))
      header
    end

    describe "choosing a format" do
      # Everything up to one chunk is written as a single encrypted value with its auth tag in
      # the header, which costs nothing per chunk.
      [0, 1, 1023, 1024].each do |size|
        it "puts the auth tag in the header for #{size} bytes" do
          write("a" * size)

          refute_predicate parsed_header, :chunked?
          assert_predicate parsed_header, :authenticated?
        end
      end

      [1025, 2048, 5000].each do |size|
        it "chunks #{size} bytes" do
          write("a" * size)

          assert_predicate parsed_header, :chunked?
          refute_predicate parsed_header, :authenticated?
          assert_equal 1024, parsed_header.chunk_size
        end
      end
    end

    describe "round trip" do
      [0, 1, 1023, 1024, 1025, 2048, 2049, 5127].each do |size|
        it "reads back #{size} bytes" do
          data = size.zero? ? "" : OpenSSL::Random.random_bytes(size)
          write(data)

          assert_equal data, SymmetricEncryption::Reader.open(the_file_name, &:read).to_s
        end
      end

      it "round trips compressed data" do
        text = "The quick brown fox. " * 5000
        SymmetricEncryption::Writer.open(the_file_name, compress: true, chunk_size: 1024) do |file|
          file.write(text)
        end

        assert_equal text, SymmetricEncryption::Reader.open(the_file_name, &:read)
      end

      it "round trips data written in many small pieces" do
        pieces = Array.new(500) { |i| "piece #{i}," }
        SymmetricEncryption::Writer.open(the_file_name, chunk_size: 1024) do |file|
          pieces.each { |piece| file.write(piece) }
        end

        assert_equal pieces.join, SymmetricEncryption::Reader.open(the_file_name, &:read)
      end
    end

    # A chunk is held in memory and handed out in pieces, so that the caller can ask for whatever
    # number of bytes it likes without the chunk being decrypted more than once.
    describe "reading part of a chunk" do
      [1, 7, 100, 1024, 2048].each do |length|
        it "reads #{length} bytes at a time" do
          write(the_data)

          buffer = "".b
          SymmetricEncryption::Reader.open(the_file_name) do |file|
            buffer << file.read(length) until file.eof?
          end

          assert_equal the_data, buffer
        end
      end

      it "reads lines that span chunks" do
        lines = Array.new(2000) { |i| "line #{i} #{'x' * 40}\n" }.join
        write(lines)

        read = []
        SymmetricEncryption::Reader.open(the_file_name) { |file| file.each_line { |line| read << line } }

        assert_equal lines, read.join
        assert_equal 2000, read.size
      end

      it "rewinds" do
        write(the_data)

        SymmetricEncryption::Reader.open(the_file_name) do |file|
          file.read(10)
          file.rewind

          assert_equal the_data, file.read
        end
      end

      it "seeks" do
        write(the_data)

        SymmetricEncryption::Reader.open(the_file_name) do |file|
          file.seek(the_chunk_size + 5)

          assert_equal the_data.byteslice((the_chunk_size + 5)..), file.read
        end
      end
    end

    describe "detecting changes" do
      def refutes_reading(file_name = the_file_name)
        assert_raises(SymmetricEncryption::CipherError, OpenSSL::Cipher::CipherError) do
          SymmetricEncryption::Reader.open(file_name, &:read)
        end
      end

      it "detects a changed byte" do
        write(the_data)
        buffer = File.binread(the_file_name)
        buffer.setbyte(buffer.bytesize - 30, buffer.getbyte(buffer.bytesize - 30) ^ 0xFF)
        File.binwrite(the_file_name, buffer)

        refutes_reading
      end

      # Whether a chunk is the last one is part of what it is authenticated against, so the chunk
      # left at the end of a truncated stream fails: it was encrypted as a middle chunk.
      it "detects a truncated stream" do
        write(the_data)
        buffer = File.binread(the_file_name)
        File.binwrite(the_file_name, buffer.byteslice(0, buffer.bytesize - (the_chunk_size + 16)))

        refutes_reading
      end

      it "detects a stream truncated part way through an auth tag" do
        write(the_data)
        buffer = File.binread(the_file_name)
        File.binwrite(the_file_name, buffer.byteslice(0, buffer.bytesize - 4))

        refutes_reading
      end

      it "detects a changed header" do
        write(the_data)
        buffer = File.binread(the_file_name)
        # Turn on the compressed flag, which lives in the header that every chunk covers.
        buffer.setbyte(5, buffer.getbyte(5) | 0b1000_0000)
        File.binwrite(the_file_name, buffer)

        refutes_reading
      end
    end

    # The chunk primitive on its own, where a chunk can be moved somewhere it never belonged.
    describe "#decrypt" do
      let :the_stream do
        SymmetricEncryption::ChunkedStream.new(
          cipher_name:  "aes-256-gcm",
          key:          "12345678901234567890123456789012",
          nonce_prefix: "1234567",
          header_bytes: "the header",
          chunk_size:   the_chunk_size
        )
      end

      let :the_first_chunk do
        the_stream.encrypt(0, "chunk zero", last: false)
      end

      it "round trips" do
        assert_equal "chunk zero", the_stream.decrypt(0, the_first_chunk, last: false)
      end

      it "adds only the auth tag to each chunk" do
        assert_equal SymmetricEncryption::Header::AUTH_TAG_SIZE, the_first_chunk.bytesize - "chunk zero".bytesize
      end

      it "detects a chunk that has been moved" do
        assert_raises OpenSSL::Cipher::CipherError do
          the_stream.decrypt(1, the_first_chunk, last: false)
        end
      end

      it "detects a chunk that is claimed to be the last" do
        assert_raises OpenSSL::Cipher::CipherError do
          the_stream.decrypt(0, the_first_chunk, last: true)
        end
      end

      it "detects a chunk from another stream" do
        other = SymmetricEncryption::ChunkedStream.new(
          cipher_name:  "aes-256-gcm",
          key:          "12345678901234567890123456789012",
          nonce_prefix: "7654321",
          header_bytes: "the header",
          chunk_size:   the_chunk_size
        )

        assert_raises OpenSSL::Cipher::CipherError do
          other.decrypt(0, the_first_chunk, last: false)
        end
      end

      it "detects a chunk too short to hold an auth tag" do
        error = assert_raises SymmetricEncryption::CipherError do
          the_stream.decrypt(0, "short", last: true)
        end

        assert_includes error.message, "truncated"
      end

      it "refuses an unauthenticated cipher" do
        assert_raises ArgumentError do
          SymmetricEncryption::ChunkedStream.new(
            cipher_name:  "aes-256-cbc",
            key:          "12345678901234567890123456789012",
            nonce_prefix: "1234567",
            header_bytes: "the header"
          )
        end
      end

      it "refuses a nonce prefix of the wrong length" do
        assert_raises ArgumentError do
          SymmetricEncryption::ChunkedStream.new(
            cipher_name:  "aes-256-gcm",
            key:          "12345678901234567890123456789012",
            nonce_prefix: "too short",
            header_bytes: "the header"
          )
        end
      end
    end

    describe "chunk size" do
      it "is rejected when it is not a power of two" do
        assert_raises SymmetricEncryption::CipherError do
          SymmetricEncryption::Header.new(version: the_cipher.version, chunk_size: 5000)
        end
      end

      it "is rejected when it is too small" do
        assert_raises SymmetricEncryption::CipherError do
          SymmetricEncryption::Header.new(version: the_cipher.version, chunk_size: 512)
        end
      end

      it "is rejected when it is too large" do
        assert_raises SymmetricEncryption::CipherError do
          SymmetricEncryption::Header.new(version: the_cipher.version, chunk_size: 32 * 1024 * 1024)
        end
      end

      it "round trips through the header" do
        header = SymmetricEncryption::Header.new(version: the_cipher.version, iv: "1234567", chunk_size: 4096)

        parsed = SymmetricEncryption::Header.new
        parsed.parse(header.to_s)

        assert_predicate parsed, :chunked?
        assert_equal 4096, parsed.chunk_size
      end
    end

    # An authenticated stream needs a new nonce for every stream, and a fixed one cannot provide
    # it. Silently ignoring the request would leave the caller expecting something else.
    it "refuses to write a stream without a random iv" do
      assert_raises ArgumentError do
        SymmetricEncryption::Writer.open(the_file_name, random_key: false, random_iv: false) do |file|
          file.write("Hello World")
        end
      end
    end
  end
end
