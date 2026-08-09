---
layout: default
---

## Files and Streams
{:.no_toc}

**Contents**

* TOC
{:toc}

`SymmetricEncryption::Writer` and `SymmetricEncryption::Reader` encrypt and decrypt entire files
and IO streams. Data is processed a block at a time, so files larger than available memory are
handled without loading them into memory.

Every file or stream written by `Writer` begins with a header that carries a randomly generated
key and initialization vector, encrypted with the configured cipher, along with the cipher version
and whether the data was compressed. Because the key and iv are random per file, encrypting the
same file twice produces different output, and `Reader` needs nothing beyond the configuration to
read it back. Key rotation does not invalidate existing files: the version in the header selects
the cipher used to decrypt.

For encrypting and decrypting files from a shell, see the [Command Line](cli.html),
which uses the same classes.

If encryption is one step in a larger pipeline, reach for
[IOStreams](https://iostreams.reidmorrison.com/) instead of using `Writer` and `Reader` directly.
See [Streaming with IOStreams](#streaming-with-iostreams) below.

## Step 1: Encrypt a file

Encrypt an existing file on disk. The contents are streamed, so the file is never fully loaded
into memory:

~~~ruby
SymmetricEncryption::Writer.encrypt(source: "customers.csv", target: "customers.csv.enc")
~~~

Returns the number of unencrypted bytes read from the source.

Write data directly, instead of copying an existing file:

~~~ruby
SymmetricEncryption::Writer.open("customers.csv.enc") do |file|
  file.write "id,name\n"
  file.write "1,Jack\n"
end
~~~

Write a string that is already in memory:

~~~ruby
SymmetricEncryption::Writer.write("secret.enc", "Keep this safe")
~~~

## Step 2: Decrypt a file

Decrypt an entire file to another file:

~~~ruby
SymmetricEncryption::Reader.decrypt(source: "customers.csv.enc", target: "customers.csv")
~~~

Read a line at a time, without writing an unencrypted copy to disk:

~~~ruby
SymmetricEncryption::Reader.open("customers.csv.enc") do |file|
  file.each_line { |line| puts line }
end
~~~

Read the entire decrypted file into memory. Not recommended for large files:

~~~ruby
data = SymmetricEncryption::Reader.read("customers.csv.enc")
~~~

## Step 3: Compress before encrypting

Compression is applied before encryption, and is on by default. `Reader` decompresses
automatically: the header records whether the data was compressed, so nothing needs to be
supplied when reading.

The default is `false` only when the target file name ends in an extension that indicates the
data is already compressed (`.zip`, `.gz`, `.gzip`, and the zip based Excel formats such as
`.xlsx`). A stream has no file name to go by, so it is always compressed unless told otherwise.
Set `compress` explicitly to override either default:

~~~ruby
SymmetricEncryption::Writer.encrypt(source: "photo.jpg", target: "photo.jpg.enc", compress: false)
~~~

## Step 4: Detect changes to an encrypted file

`aes-256-cbc`, the cipher used before v5, keeps a file secret but does not detect changes to it. Anyone
who can write to the file can change it, and what comes back out is whatever those changed bytes
decrypt to.

Configuring an authenticated cipher, `aes-256-gcm`, changes that: a file that has been tampered
with, or truncated, fails to decrypt instead of returning data. Nothing about the code above
changes, files are simply written and read as before. See
[Security](security.html) for how a stream of any size is
verified as it is read.

## Step 5: Use a stream instead of a file

Anywhere a file name is accepted, an IO stream can be supplied instead. This is how encrypted
data is produced for, or consumed by, a library that works with streams rather than paths.

Encrypt a file on disk into memory:

~~~ruby
require "stringio"

buffer = StringIO.new(+"".b)
SymmetricEncryption::Writer.encrypt(source: "customers.csv", target: buffer)

encrypted = buffer.string
~~~

Note that `buffer` is closed when the block completes, since `Writer` closes the stream it was
given. `StringIO#string` is still readable afterwards. To keep the stream open, build the writer
with `.new` instead of `.open` and call `close(false)`.

Decrypt from a stream:

~~~ruby
SymmetricEncryption::Reader.read(StringIO.new(encrypted))
~~~

### Who closes what

* `Writer.open` and `Reader.open` **with a block** close both the encrypted stream and the
  underlying file or stream when the block completes.
* **Without a block** they return the reader or writer and closing it is the caller's
  responsibility. Calling `close` on it also closes the underlying stream.
* `close(false)` closes only the encryption layer and leaves the underlying stream open. `Writer`
  must be closed before the stream beneath it, since closing is what writes the final block.

## What `Reader.open` yields

`Reader.open` yields one of two objects, depending on whether the data was compressed:

* `Zlib::GzipReader` for compressed data, which is the default for anything this gem writes.
* `SymmetricEncryption::Reader` otherwise.

Both support `read`, `read(length)`, `read(length, outbuf)`, `gets`, `readline`, `each_line`,
`eof?`, `pos`, `rewind`, `close` and `closed?`, which is enough for `IO.copy_stream` and for most
libraries that accept a stream. Neither is a complete IO implementation, and beyond that common
set they differ:

| Method | `SymmetricEncryption::Reader` | `Zlib::GzipReader` |
|---|---|---|
| `seek`, `size`, `flush` | yes | no |
| `readpartial`, `getc`, `readbyte`, `getbyte`, `readlines`, `to_io`, `external_encoding` | no | yes |
| `path`, `fileno`, `binmode`, `set_encoding` | no | no |

Since compression is the default, code that works against an encrypted file written by this gem
should not rely on `seek` or `size`. If a library needs a method that neither provides, decrypt to
a `Tempfile` first and hand it a real `File`.

`seek` also differs in cost. On a stream encrypted with `aes-256-gcm` it jumps straight to the
chunk holding the offset, however far into the file that is. On any other stream it re-reads the
file up to that point, and `IO::SEEK_END` reads the whole file to find out how long it is. See
[Seeking](security.html#seeking).

### Encoding

The decrypted bytes are always exact, but the encoding they are tagged with depends on which of
the two objects produced them. `SymmetricEncryption::Reader#read` returns `ASCII-8BIT` for data
containing non-ASCII bytes, while `Zlib::GzipReader#read` tags its result with the default
external encoding, usually `UTF-8`, even for data that is not text at all. So a compressed read
compares unequal to the original binary string despite holding identical bytes, and an
uncompressed read raises `Encoding::UndefinedConversionError` when written to a file opened with a
text encoding.

Avoid both by never routing binary content through a String. Decrypt straight to the target:

~~~ruby
SymmetricEncryption::Reader.decrypt(source: "photo.jpg.enc", target: "photo.jpg")
~~~

Or, when the target is a stream, open it in binary mode:

~~~ruby
SymmetricEncryption::Reader.open("photo.jpg.enc") do |input|
  File.open("photo.jpg", "wb") do |output|
    IO.copy_stream(input, output)
  end
end
~~~

Where a String is unavoidable, call `.b` on it before comparing it with, or appending it to, other
binary data.

## Sending encrypted data to an HTTP client

Most HTTP clients accept a readable IO as the request body. `Net::HTTP` requires either a
`Content-Length` or `Transfer-Encoding: chunked` when `body_stream` is used.

Encrypt to a temporary file, then upload it. The encrypted size is known up front, so
`Content-Length` can be set:

~~~ruby
require "tempfile"

Tempfile.create(["upload", ".enc"]) do |encrypted|
  SymmetricEncryption::Writer.encrypt(source: "customers.csv", target: encrypted.path)

  File.open(encrypted.path, "rb") do |io|
    request                 = Net::HTTP::Post.new(uri)
    request["Content-Type"] = "application/octet-stream"
    request.content_length  = File.size(encrypted.path)
    request.body_stream     = io

    Net::HTTP.start(uri.host, uri.port, use_ssl: true) { |http| http.request(request) }
  end
end
~~~

To avoid writing the encrypted copy to disk at all, encrypt through a pipe and send it chunked.
Nothing larger than the pipe buffer is held in memory:

~~~ruby
read_io, write_io = IO.pipe

producer = Thread.new do
  SymmetricEncryption::Writer.open(write_io) do |file|
    IO.copy_stream("customers.csv", file)
  end
end

request                      = Net::HTTP::Post.new(uri)
request["Transfer-Encoding"] = "chunked"
request.body_stream          = read_io

Net::HTTP.start(uri.host, uri.port, use_ssl: true) { |http| http.request(request) }
producer.join
~~~

## Sending decrypted data to another library

To pass the decrypted contents of a file to a library or method that reads a stream, hand it the
reader itself. Nothing is written to disk and the whole file is not held in memory:

~~~ruby
SymmetricEncryption::Reader.open("customers.csv.enc") do |io|
  other_library(io)
end
~~~

The same applies to a Rails controller that streams a decrypted file to the browser:

~~~ruby
def download
  SymmetricEncryption::Reader.open(document.path) do |io|
    send_data io.read, filename: "customers.csv", type: "text/csv"
  end
end
~~~

When uploading a decrypted stream, use chunked encoding. The decrypted size is not known before
the file has been read, and in particular it is **not** the size of the encrypted file:

~~~ruby
SymmetricEncryption::Reader.open("customers.csv.enc") do |io|
  request                      = Net::HTTP::Post.new(uri)
  request["Transfer-Encoding"] = "chunked"
  request.body_stream          = io

  Net::HTTP.start(uri.host, uri.port, use_ssl: true) { |http| http.request(request) }
end
~~~

Setting `request.content_length = File.size("customers.csv.enc")` here silently truncates the
upload to the size of the encrypted file, which is smaller than the plaintext whenever the file
was compressed.

## CSV files

`CSV` accepts the reader and the writer directly. Supply `row_sep` when writing, otherwise `CSV`
attempts to read from and rewind the output stream:

~~~ruby
require "csv"

SymmetricEncryption::Writer.open("customers.csv.enc") do |file|
  csv = CSV.new(file, row_sep: "\n")
  csv << %w[id name]
  csv << [1, "Jack"]
end

SymmetricEncryption::Reader.open("customers.csv.enc") do |file|
  CSV.new(file).each { |row| p row }
end
~~~

## Streaming with IOStreams

`Writer` and `Reader` encrypt and decrypt. They do not know about compression formats other than
gzip, file formats, or where the file lives. The sister project
[IOStreams](https://iostreams.reidmorrison.com/) does, and has direct support for Symmetric
Encryption built in. Prefer it whenever encryption is one step among several.

Add both gems to the `Gemfile`. IOStreams treats `symmetric-encryption` as a soft dependency and
only loads it when a `.enc` file is read or written:

~~~ruby
gem "iostreams"
gem "symmetric-encryption"
~~~

IOStreams derives the pipeline from the file name extensions, so `.enc` alone selects Symmetric
Encryption, using the same configuration this gem already loaded:

~~~ruby
require "iostreams"

IOStreams.path("customers.csv.enc").writer do |io|
  io.write("id,name\n")
end

IOStreams.path("customers.csv.enc").read
~~~

Extensions combine, and are applied in order. Reading `customers.csv.gz.enc` decrypts first and
then decompresses, and writing it does the reverse:

~~~ruby
IOStreams.path("customers.csv.gz.enc").reader { |io| io.read }
~~~

The file format and the storage location are extensions of the same idea, which is what makes
IOStreams worth reaching for. A record at a time out of an encrypted, compressed CSV held in S3,
never landing on local disk and never held in memory in full:

~~~ruby
IOStreams.path("s3://my-bucket/customers.csv.gz.enc").each(:hash) do |record|
  puts record["name"]
end
~~~

IOStreams also handles PGP, Zip and BZip2, reads Excel spreadsheets, and reads and writes over
SFTP and HTTP. See the [IOStreams tutorial](https://iostreams.reidmorrison.com/tutorial) and the
[list of supported extensions](https://iostreams.reidmorrison.com/extensions).

Use `Writer` and `Reader` from this gem directly when encryption is all that is needed, when the
encrypted data has no file name to infer a pipeline from, or when adding another dependency is not
worthwhile.

## Reading files encrypted without a header

Files written by other tools, or by `Writer` with `header: false`, carry no version information.
Supply the cipher version explicitly when reading them:

~~~ruby
SymmetricEncryption::Reader.read("legacy.enc", version: 0)
~~~

Symmetric Encryption never guesses which cipher to use. Decrypting with the wrong key can appear
to succeed and return meaningless data, so a file with no header and no `version` uses the
current primary cipher and fails loudly if that is not the one it was encrypted with.

## Next steps

* [Security](security.html): authenticated encryption, and verifying a stream as it is read.
* [Command Line](cli.html): encrypting and decrypting files from a shell.
* [Guide](guide.html): the library, one step at a time.
* [API](api.html): the full `Writer` and `Reader` reference.
