---
layout: default
---

## API
{:.no_toc}

**Contents**

* TOC
{:toc}

Reference for the methods this gem exposes. For a walk through of how to use them, start with the
[Guide](guide.html).

## SymmetricEncryption.encrypt

~~~ruby
SymmetricEncryption.encrypt(value, random_iv: SymmetricEncryption.randomize_iv?, compress: false,
                            type: :string, version: nil, header: nil)
~~~

Encrypts the supplied value and encodes the result.

Returns the encoded, encrypted value. Base64 text for every encoding other than `:none`, which
returns raw binary. Returns `nil` when the value is `nil`, and `""` when it is an empty string.

| Parameter | Description |
|---|---|
| `value` | The value to encrypt. Anything that is not a String has `#to_s` called on it, unless `type:` says otherwise. |
| `random_iv` | Use a new random initialization vector every time, so the same input does not encrypt to the same output. Set to `false` when the value must be searchable. Default: `SymmetricEncryption.randomize_iv?`, itself `false` unless configured otherwise. |
| `compress` | Compress before encrypting. Worth it only for large values. Default: `false` |
| `type` | The type of the value being encrypted. One of `SymmetricEncryption::COERCION_TYPES`. Default: `:string` |
| `version` | Encrypt with the configured cipher that has this version, rather than the primary one. The version is written into the header, so nothing is needed when decrypting. Default: the primary cipher. |
| `header` | Whether to add the header. Default: the cipher's `always_add_header`, itself `true`. |

A header is added regardless of `header:` whenever it is needed to decrypt the value again: when
`random_iv` or `compress` is true, or when the cipher is an authenticated one.

~~~ruby
SymmetricEncryption.encrypt("Hello World")
# => "QEVuQwAANIuPIXv/ii1IP1dF6T0NpQ=="

SymmetricEncryption.encrypt(21, type: :integer)
SymmetricEncryption.encrypt("Hello World", random_iv: true, compress: true)
~~~

### Size

An encrypted value is longer than its input. Base64 expands by roughly a third, and the header adds:

| | Header size |
|---|---|
| Header only | 6 bytes |
| With a random IV, `aes-256-cbc` | 24 bytes |

`random_iv: true` adds 2 bytes for the length plus the initialization vector itself, which is 16
bytes for `aes-256-cbc`. An encrypted key or cipher name in the header adds more again.

## SymmetricEncryption.decrypt

~~~ruby
SymmetricEncryption.decrypt(encrypted_and_encoded_string, version: nil, type: :string)
~~~

Decodes and decrypts the supplied value.

Returns the decrypted value, coerced to `type`. Returns `nil` when the value is `nil`, and `""` when
it is an empty string.

| Parameter | Description |
|---|---|
| `encrypted_and_encoded_string` | The value to decrypt. |
| `version` | Which cipher to decrypt with, for a value that has **no header**. Ignored when the value has one, since the header names its own version. |
| `type` | The type the value was encrypted as. Must match what was supplied to `encrypt`. Default: `:string` |

Raises `OpenSSL::Cipher::CipherError` when the value cannot be decrypted, and
`SymmetricEncryption::CipherError` when no configured cipher has the version the header asks for.

**Decryption never falls back to another cipher when one fails.** Decrypting with the wrong key can
quietly succeed and return meaningless data, so a failure is reported rather than guessed at.

## SymmetricEncryption.try_decrypt

~~~ruby
SymmetricEncryption.try_decrypt(str)
~~~

As `decrypt`, but returns `nil` instead of raising when the value cannot be decrypted.

Intended for configuration files that hold passwords for several environments, where the current
environment holds the key for only one of them:

~~~yaml
password: <%= SymmetricEncryption.try_decrypt("QEVuQwJAEACOYREfF1cAXU0B...") %>
~~~

The value it returns should not be relied upon, since it is possible to decrypt data with the wrong
key and get something back.

## SymmetricEncryption.encrypted?

~~~ruby
SymmetricEncryption.encrypted?(value)
~~~

Returns whether the value was encrypted by this library, by looking for the header. It does not
attempt to decrypt, so it is cheap and does not need the right key.

~~~ruby
SymmetricEncryption.encrypted?("QEVuQwAANIuPIXv/ii1IP1dF6T0NpQ==")
# => true
SymmetricEncryption.encrypted?("Hello World")
# => false
~~~

Only reliable for values that carry a header, which is the default. `nil` and `""` return `false`.

## SymmetricEncryption.with_cipher

~~~ruby
SymmetricEncryption.with_cipher(cipher, secondary_ciphers: []) { ... }
~~~

Uses the supplied cipher for the duration of the block instead of the configured primary cipher.

Intended for data encrypted with a key of its own, held somewhere other than
`symmetric-encryption.yml`, such as a key per customer read from a database table. See
[Key Rotation](key_rotation.html#a-key-per-customer).

~~~ruby
SymmetricEncryption.with_cipher(customer.cipher) do
  person.save!
end
~~~

Everything encrypted or decrypted inside the block uses that cipher, including Active Record
attributes, Mongoid fields, files and streams. The configured ciphers are still searched when
decrypting, so data encrypted before the block is still readable inside it.

Threads and fibers started inside the block inherit the scope. A thread that already existed does
not, so handing work to a thread pool inside the block runs that work **without** the scope.

## SymmetricEncryption.cipher

~~~ruby
SymmetricEncryption.cipher            # The primary cipher
SymmetricEncryption.cipher(3)         # The configured cipher with version 3
SymmetricEncryption.cipher?           # Whether a primary cipher has been set
SymmetricEncryption.secondary_ciphers # Ciphers that are only ever decrypted with
~~~

`cipher(version)` raises `SymmetricEncryption::CipherError` when no configured cipher has that
version, naming the versions that are available.

## SymmetricEncryption.load!

~~~ruby
SymmetricEncryption.load!(file_name = nil, env = nil)
~~~

Loads the configuration. Not needed in Rails, where the railtie does it during boot.

~~~ruby
SymmetricEncryption.load!("config/symmetric-encryption.yml", "production")
~~~

Defaults to `Rails.root/config/symmetric-encryption.yml` and `Rails.env`, honouring
`SYMMETRIC_ENCRYPTION_CONFIG` and `SYMMETRIC_ENCRYPTION_ENV`.

## SymmetricEncryption.random_password

~~~ruby
SymmetricEncryption.random_password(size = 22)
~~~

Returns a random URL-safe base64 password.

## Settings

~~~ruby
SymmetricEncryption.cipher = cipher            # Set the primary cipher directly
SymmetricEncryption.secondary_ciphers = [...]  # Ciphers that are only decrypted with
SymmetricEncryption.randomize_iv = true        # Default for random_iv:. Default: false
SymmetricEncryption.filter_encrypted_attributes = false  # See below. Default: true
SymmetricEncryption.select_cipher { |encoded, decoded| ... }  # For headerless values
~~~

`filter_encrypted_attributes` controls whether Active Record attributes declared `:encrypted` are
added to the model's `filter_attributes`. It is applied when the attribute is declared, so it has to
be set before the models are loaded. See [Rails](rails.html#keeping-values-out-of-logs).

## Writer and Reader

Encrypt and decrypt files and IO streams. See [Files](files.html) for the full treatment.

~~~ruby
SymmetricEncryption::Writer.open(file_name_or_stream, compress: nil, **args) { |file| ... }
SymmetricEncryption::Writer.write(file_name_or_stream, data, **args)
SymmetricEncryption::Writer.encrypt(source:, target:, **args)

SymmetricEncryption::Reader.open(file_name_or_stream, buffer_size: 16_384, **args) { |file| ... }
SymmetricEncryption::Reader.read(file_name_or_stream, **args)
SymmetricEncryption::Reader.decrypt(source:, target:, **args)
SymmetricEncryption::Reader.empty?(file_name_or_stream)
SymmetricEncryption::Reader.header_present?(file_name)
~~~

`Writer.encrypt` and `Reader.decrypt` both return the number of **unencrypted** bytes that passed
through them, not the size of the encrypted file.

`Writer.new` accepts `version:`, `cipher_name:`, `header:`, `random_key:`, `random_iv:`, `compress:`
and `chunk_size:`. `Reader.new` accepts `buffer_size:` and `version:`.

## Cipher

Building a cipher by hand, rather than loading one from the configuration file:

~~~ruby
SymmetricEncryption::Cipher.new(
  key:               "...",              # Required. Raw binary, exactly the cipher's key length.
  iv:                "...",              # Optional. Raw binary, exactly the cipher's iv length.
  cipher_name:       "aes-256-cbc",      # Default: aes-256-cbc
  version:           0,                  # 0..255. Default: 0
  always_add_header: true,               # Default: true
  encoding:          :base64strict       # Default: :base64strict
)
~~~

Encodings: `:base64strict`, `:base64`, `:base64urlsafe`, `:base16`, `:none`.

`key` and `iv` are raw binary data of an exact length, not text. See
[Configuration](configuration.html#supplying-the-key-in-the-configuration-file).

## Coercion types

`SymmetricEncryption::COERCION_TYPES`:

| Type | Ruby class |
|---|---|
| `:string` | `String` |
| `:integer` | `Integer` |
| `:float` | `Float` |
| `:decimal` | `BigDecimal` |
| `:datetime` | `DateTime` |
| `:time` | `Time` |
| `:date` | `Date` |
| `:boolean` | `TrueClass` or `FalseClass` |
| `:json` | Serialized with JSON |
| `:yaml` | Serialized with YAML |

## Next steps

* [Guide](guide.html): these methods in context.
* [Files](files.html): `Writer` and `Reader` in depth.
* [Configuration](configuration.html): the configuration file and the keystores.
