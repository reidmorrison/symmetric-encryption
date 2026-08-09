---
layout: default
---

## Authenticated Encryption

`aes-256-cbc`, the default cipher, keeps data secret but does not detect changes to it. Anyone
who can write to the encrypted value can change it, and the value that comes back out of
`SymmetricEncryption.decrypt` is whatever those changed bytes decrypt to.

An authenticated cipher, `aes-256-gcm`, produces an auth tag along with the encrypted data. The
tag is checked when the value is decrypted, and decryption fails if anything at all has changed.

~~~yaml
production:
  ciphers:
    - key_filename:       /etc/symmetric-encryption/production_v2.key
      cipher_name:        aes-256-gcm
      version:            2
      encoding:           :base64strict
      always_add_header:  true
      key_encrypting_key:
        aws:
          master_key_alias: alias/symmetric-encryption/production
~~~

Nothing else changes. `SymmetricEncryption.encrypt` and `attribute :ssn, :encrypted` behave
exactly as before:

~~~ruby
encrypted = SymmetricEncryption.encrypt("Hello World")
SymmetricEncryption.decrypt(encrypted)
# => "Hello World"
~~~

### What is protected

The auth tag covers the encrypted data _and_ the header, so the version, the compression flag,
the initialization vector and the cipher name cannot be changed either. Decrypting a value that
has been tampered with anywhere raises `OpenSSL::Cipher::CipherError` instead of returning data:

~~~ruby
SymmetricEncryption.decrypt(tampered_value)
# OpenSSL::Cipher::CipherError
~~~

The auth tag is always the full 16 bytes. OpenSSL accepts a shorter one, and a truncated tag is
not expensive to forge, so a value carrying a short tag is rejected rather than trusted.

An authenticated cipher also refuses to decrypt a value that has no auth tag at all. Without
that check, removing the tag would be enough to skip the check entirely.

### Encrypted values are always larger

An authenticated value always carries a header, whatever `always_add_header` is set to, because
that is where the auth tag lives. Expect roughly 30 bytes more per value than `aes-256-cbc` with
no header: 6 bytes of header, 2 + 12 bytes of initialization vector, and 2 + 16 bytes of auth tag.

### Values that have to be queried

A value that is used in a `where` clause has to encrypt to the same ciphertext every time, which
is what `random_iv: false` is for:

~~~ruby
class User < ActiveRecord::Base
  attribute :api_key, :encrypted, random_iv: false
end

User.where(api_key: SymmetricEncryption.encrypt("secret", random_iv: false))
~~~

This works with `aes-256-gcm`, but it does not work the way it does for `aes-256-cbc`. Re-using
one initialization vector across different values is far more damaging for an authenticated
cipher than it is for `aes-256-cbc`: it exposes the encrypted data and makes the auth tag
forgeable. So the initialization vector is derived from the value being encrypted rather than
taken from the configuration. The same value still encrypts to the same result, which is what
makes the query work, and two different values never share an initialization vector.

A configured `iv:` is therefore ignored by an authenticated cipher. Every value gets its own.

Unlike Active Record encryption, the key for these values can still be rotated. See
[Key Rotation](key_rotation.html).

### Files and streams are not supported

`SymmetricEncryption::Writer` and `SymmetricEncryption::Reader` refuse an authenticated cipher:

~~~ruby
SymmetricEncryption::Writer.open("file.enc") { |file| file.write("data") }
# ArgumentError: AES-256-GCM is an authenticated cipher, which is not supported for files and streams.
~~~

The auth tag of an authenticated cipher only exists once everything has been encrypted, and it
can only be checked once everything has been decrypted. A file read as a stream would therefore
have to hand out data long before there was any way to know whether it had been tampered with,
which is the one thing the cipher is there to prevent. Rather than quietly giving up that
guarantee, streaming with an authenticated cipher is refused.

Encrypt the file itself with an unauthenticated cipher instead:

~~~ruby
SymmetricEncryption::Writer.open("file.enc", cipher_name: "aes-256-cbc") do |file|
  file.write("data")
end
~~~

Every file already gets its own randomly generated key, and that key is encrypted with the global
cipher and stored in the file's header. So the file's key is still protected by the authenticated
global cipher, even though the file's contents are encrypted with `aes-256-cbc`.

### Moving existing data to an authenticated cipher

Data already encrypted with `aes-256-cbc` cannot be decrypted by an `aes-256-gcm` cipher. Add
the new cipher as described in [Key Rotation](key_rotation.html) and keep the old one in
`symmetric-encryption.yml` as a secondary cipher. Every value carries the version of the cipher
that encrypted it in its header, so old values continue to be read by the old cipher while new
values are encrypted with the new one.

Values written before headers were enabled carry no version, so they can only be read by
supplying the version explicitly:

~~~ruby
SymmetricEncryption.decrypt(old_value, version: 1)
~~~

### Next => [Key Rotation](key_rotation.html)
