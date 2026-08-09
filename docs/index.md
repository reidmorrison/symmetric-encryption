---
layout: default
---

## What is Symmetric Encryption?
{:.no_toc}

**Contents**

* TOC
{:toc}

Symmetric Encryption encrypts data at rest in Ruby and Rails applications, using OpenSSL, with the
encryption keys held outside of the source code.

It covers four things:

1. **Model attributes.** Active Record attributes and Mongoid fields that are encrypted in the
   database and decrypted transparently when read.
2. **Passwords in configuration files.** Including the database password in `database.yml`, which is
   decrypted before Rails has finished booting.
3. **Whole files and streams.** Of any size, encrypted and decrypted as they are read or written,
   without loading them into memory.
4. **Key rotation.** Every encrypted value records which key encrypted it, so a new key can be
   introduced and the old one retired without taking the application down.

## Do you need it?

Rails 7 added [Active Record encryption](https://guides.rubyonrails.org/active_record_encryption.html),
which encrypts model attributes with no gem at all. **If everything you need to encrypt is an Active
Record attribute, use Active Record encryption.** It is built in, it is maintained by the Rails team,
and this gem does not do that job better.

Symmetric Encryption is for the encryption Active Record encryption does not cover:

* **Mongoid fields**, without deploying MongoDB's client side field level encryption, which needs
  `libmongocrypt` and a key management service before it will encrypt anything.
* **Whole files and streams**, of any size, without reading them into memory.
* **Standalone Ruby**, with no Rails and no Active Record.
* **Passwords in `database.yml`** and other configuration files, decrypted before Rails has finished
  booting, which is what makes an encrypted database password possible.
* **Data encryption keys held in AWS KMS or Google Cloud KMS.**
* **Rotating the key for a value that has to encrypt to the same ciphertext every time** so that it
  can be queried. Active Record encryption cannot rotate its deterministic key.

Already using this gem for Active Record attributes and want to move to Active Record encryption?
See [Migrating to Active Record encryption](rails.html#migrating-to-active-record-encryption),
which reads the data already in the database while Active Record encryption writes every new value.

## Quick start

### 1. Install

~~~ruby
gem "symmetric-encryption"
~~~

Then `bundle install`. Ruby 3.2 or later is required, and Rails 7.2 or later if you are using Rails.

### 2. Encrypt something

Before generating any keys, you can try the library with a throwaway key. Paste this into `irb`:

~~~ruby
require "symmetric_encryption"

SymmetricEncryption.cipher = SymmetricEncryption::Cipher.new(
  key:         "1234567890ABCDEF",
  iv:          "1234567890ABCDEF",
  cipher_name: "aes-128-cbc"
)

encrypted = SymmetricEncryption.encrypt("Hello World")
# => "QEVuQwAANIuPIXv/ii1IP1dF6T0NpQ=="

SymmetricEncryption.decrypt(encrypted)
# => "Hello World"
~~~

That key is in this documentation, so it is not a secret. It is only for seeing the library work.

### 3. Generate real keys

~~~
symmetric-encryption --generate --app-name my_app
~~~

This writes `config/symmetric-encryption.yml`, which belongs in source control, and one key file per
environment under `~/.symmetric-encryption`, which does not. See
[Configuration](configuration.html).

### 4. Encrypt a database column

The column is a `string`, whatever the attribute's type, because the encrypted value is always text:

~~~ruby
class AddSsnToPeople < ActiveRecord::Migration[8.0]
  def change
    add_column :people, :ssn, :string
  end
end
~~~

~~~ruby
class Person < ActiveRecord::Base
  attribute :ssn, :encrypted
end
~~~

That is the whole change. Reads and writes look exactly like an unencrypted attribute:

~~~ruby
person = Person.create!(name: "Jack", ssn: "123456789")
person.ssn
# => "123456789"
~~~

While the database holds ciphertext:

~~~sql
SELECT ssn FROM people;
-- QEVuQwJAEACOYREfF1cAXU0B8Xre7bISBCV415agBWeiX6cF1boT2g==
~~~

Continue with the [Guide](guide.html), which builds up from here one step at a time.

## A tour of the features

**Encrypted model attributes**, cast to the type you declare, so an encrypted integer is still an
integer when you read it back:

~~~ruby
attribute :age, :encrypted, type: :integer
~~~

**Values kept out of logs and JSON.** Encrypted attributes are added to the model's
`filter_attributes` automatically, so `inspect` and the Rails logs show `[FILTERED]` rather than the
decrypted value. See [Rails](rails.html).

**Authenticated encryption** with `aes-256-gcm`, the cipher new configurations are generated with,
which detects any change to an encrypted value rather than decrypting whatever it is given. Files
and streams are authenticated a chunk at a time, so they are verified as they are read rather than
only once all of the data has been read. See [Security](security.html).

**Encrypted files and streams:**

~~~ruby
SymmetricEncryption::Writer.open("secure.enc") do |file|
  file.write("Hello World")
end
~~~

See [Files](files.html).

**Keys in a cloud KMS.** AWS KMS and Google Cloud KMS can hold the master key, so the key that
protects your data never exists in a file on your servers. See [Configuration](configuration.html).

**Key rotation without downtime**, driven from the command line. See
[Key Rotation](key_rotation.html).

**Encrypted passwords in configuration files**, including `database.yml`, decrypted early enough in
the Rails boot that the database connection can use them.

## How it works

Three pieces explain most of the library.

**The cipher.** A cipher pairs an encryption key with a version number and an encoding. The version
is what makes rotation possible. `symmetric-encryption.yml` lists the ciphers for an environment; the
first is the one that encrypts, and the rest exist so that data encrypted by earlier keys can still
be read.

**The header.** An encrypted value normally starts with a small binary header, `@EnC` followed by the
cipher version and a flags byte, before the value is base64 encoded. Decryption reads the version out
of the header and looks up the matching cipher, which is why introducing a new key does not require
re-encrypting anything. The header is 6 bytes, growing when it also carries a random initialization
vector or an encrypted key.

Because the version travels with the value, decryption never guesses. It will not try other keys when
one fails, since decrypting with the wrong key can quietly succeed and return garbage.

**The keystore.** The encryption key itself lives outside the application, in a keystore: a file on
disk, an environment variable, AWS KMS, or Google Cloud KMS. The configuration file in source control
holds only a pointer to it, or an encrypted copy of it that the keystore can unlock.

## Next steps

* [Guide](guide.html): the library, one step at a time. Start here.
* [Configuration](configuration.html): the configuration file and the keystores.
* [Rails](rails.html) and [Mongoid](mongoid.html): encrypted model attributes and fields.
* [Files](files.html): encrypted files and streams.
* [Security](security.html): authenticated encryption, threat model, and PCI compliance.

## Support

* Questions and bug reports: [GitHub Issues](https://github.com/reidmorrison/symmetric-encryption/issues)
* Source: [github.com/reidmorrison/symmetric-encryption](https://github.com/reidmorrison/symmetric-encryption)
