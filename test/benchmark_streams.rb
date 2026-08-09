# Streaming throughput for files, so that a change to the streaming code can be shown not to have
# slowed the unauthenticated path down.
#
#   bundle exec ruby test/benchmark_streams.rb
#   bundle exec ruby test/benchmark_streams.rb 256   # megabytes, default 64
require_relative "test_helper"
require "benchmark"

megabytes = (ARGV[0] || 64).to_i
# Incompressible, so that the numbers reflect the encryption rather than zlib finding a pattern
# that real data would not have.
chunk     = OpenSSL::Random.random_bytes(1024 * 1024)
file_name  = "._benchmark_stream"
iterations = 3

def report(label, bytes, seconds)
  puts format(
    "  %-28<label>s %7.3<seconds>f s  %8.1<rate>f MB/s",
    label: label, seconds: seconds, rate: bytes / 1024.0 / 1024.0 / seconds
  )
end

puts "Ruby #{RUBY_VERSION}, OpenSSL #{OpenSSL::OPENSSL_VERSION}"
puts "#{megabytes} MB per run, best of #{iterations}, cipher #{SymmetricEncryption.cipher.cipher_name}"

begin
  %w[uncompressed compressed].each do |mode|
    compress = mode == "compressed"
    puts "\n#{mode}:"

    write_times = []
    read_times  = []
    iterations.times do
      write_times << Benchmark.realtime do
        SymmetricEncryption::Writer.open(file_name, compress: compress) do |file|
          megabytes.times { file.write(chunk) }
        end
      end

      read_times << Benchmark.realtime do
        SymmetricEncryption::Reader.open(file_name) do |file|
          nil while file.read(65_536)
        end
      end
    end

    bytes = megabytes * chunk.bytesize.to_f
    report("write 1 MB at a time", bytes, write_times.min)
    report("read 64 KB at a time", bytes, read_times.min)
    puts format("  %-28<label>s %<size>s bytes on disk", label: "encrypted size", size: File.size(file_name))
  end

  # Per call overhead rather than throughput: the cost of one `write` or `read` matters as much as
  # the encryption rate when the caller works in small pieces, as CSV and line oriented code does.
  puts "\nsmall operations, uncompressed:"
  small       = chunk.byteslice(0, 100)
  small_count = megabytes * 1000
  small_bytes = (small_count * small.bytesize).to_f

  write_times = []
  read_times  = []
  iterations.times do
    write_times << Benchmark.realtime do
      SymmetricEncryption::Writer.open(file_name, compress: false) do |file|
        small_count.times { file.write(small) }
      end
    end

    read_times << Benchmark.realtime do
      SymmetricEncryption::Reader.open(file_name) do |file|
        nil while file.read(100)
      end
    end
  end

  report("write 100 bytes x #{small_count}", small_bytes, write_times.min)
  report("read 100 bytes at a time", small_bytes, read_times.min)
ensure
  FileUtils.rm_f(file_name)
end
