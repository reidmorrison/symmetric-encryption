---
layout: default
---

## Multiple Ciphers

Every cipher in `symmetric-encryption.yml` has a version, and every encrypted value records the
version of the cipher that encrypted it in its header. That is what makes
[key rotation](key_rotation.html) work, and it is also what makes it possible to encrypt
different data with different keys.

There are two quite different things people want here, and they have different answers.

### Different keys for different data

Give each key its own version in the configuration file, and encrypt with that cipher:

~~~ruby
encrypted = SymmetricEncryption.cipher(3).encrypt("Hello World")

SymmetricEncryption.decrypt(encrypted)
# => "Hello World"
~~~

Decryption needs nothing extra. The version is in the header, so the right cipher is chosen
automatically.

Files and streams take the version as an option:

~~~ruby
SymmetricEncryption::Writer.open("archive.enc", version: 3) { |file| file.write(data) }
~~~

Active Record attributes and Mongoid fields always encrypt with the primary cipher. There is no
version option on the declaration, so wrap the code that writes them instead:

~~~ruby
SymmetricEncryption.with_cipher(SymmetricEncryption.cipher(3)) do
  person.update!(api_key: "secret")
end
~~~

Reading needs no wrapper, since the version is in the header of each value.

Three things to know before relying on this:

* The command line interface treats every version as a rotation of the same key.
  `--activate-key` moves the highest version to the top, and `--cleanup-keys` removes everything
  except the highest. Both will happily throw away a key that is there for a different purpose.
  Do not use them on a configuration file that holds keys for more than one purpose.
* All of the ciphers have to use a compatible `encoding`, since a value is decoded before its
  header is read. `:base64` and `:base64strict` work together. `:base16`, `:base64urlsafe` and
  `:none` do not mix with the others.
* `SymmetricEncryption.cipher(3)` returns `nil` when no cipher has that version, so a version
  that is not in the configuration file fails with `NoMethodError` rather than saying so.

**If this is a Rails application, and the data is nothing but Active Record attributes, use
[Active Record encryption](rails_encryption.html) instead.** `encrypts :ssn, key: "..."` does the
same job, without a version number to allocate and without the two warnings above.

### A key per customer

The version is a single byte, so a configuration file holds at most 256 ciphers. That is plenty
for rotating a key, and nowhere near enough for a key per customer.

Keys held somewhere else, usually a database table and each encrypted with the global cipher,
are used with `with_cipher`:

~~~ruby
class Customer < ActiveRecord::Base
  attribute :encryption_key, :encrypted

  def cipher
    @cipher ||= SymmetricEncryption::Cipher.new(
      key:         encryption_key,
      cipher_name: "aes-256-gcm",
      version:     1
    )
  end
end

SymmetricEncryption.with_cipher(customer.cipher) do
  person.update!(ssn: "123-45-6789")
end
~~~

Everything encrypted or decrypted inside the block uses that customer's key: Active Record
attributes, Mongoid fields, files and streams alike. Data encrypted with the configured ciphers
is still readable inside the block, so a customer key does not cut the application off from
everything else it encrypted.

In a Rails application the natural place for it is around the request:

~~~ruby
class ApplicationController < ActionController::Base
  around_action :with_customer_encryption_key

  def with_customer_encryption_key(&block)
    return yield if current_customer.nil?

    SymmetricEncryption.with_cipher(current_customer.cipher, &block)
  end
end
~~~

Because the key is chosen by what is in scope rather than by what is in the data, versions no
longer have to be unique across customers. Two customers can both use version 1.

#### Use an authenticated cipher

That is also the risk. Decrypting one customer's data while another customer's cipher is in
scope decrypts it with the wrong key, and nothing in the value says which customer it belonged
to.

With `aes-256-gcm` that fails, loudly:

~~~ruby
SymmetricEncryption.with_cipher(other_customer.cipher) do
  SymmetricEncryption.decrypt(value)
end
# OpenSSL::Cipher::CipherError
~~~

With `aes-256-cbc` it cannot be detected. Decryption occasionally succeeds with the wrong key and
returns whatever that key produces. Use an authenticated cipher for anything encrypted this way.
See [Authenticated Encryption](authenticated_encryption.html).

#### Rotating a customer's key

Supply the previous key so that data encrypted with it is still readable while new data is
encrypted with the new one:

~~~ruby
SymmetricEncryption.with_cipher(customer.cipher, secondary_ciphers: [customer.previous_cipher]) do
  Person.where(customer_id: customer.id).find_each { |person| person.update_column(:ssn, person.ssn) }
end
~~~

Once nothing is left holding the old key, drop it from the call.

#### Where the scope reaches

The scope belongs to the current fiber. Threads and fibers started inside the block inherit it,
which includes Enumerators, and what they do with it does not leak back out.

A thread that already existed does not inherit it, because the scope is copied when a thread is
created. Handing work to a thread pool, or to a background job, runs that work without the
scope. Set it again there:

~~~ruby
class PersonJob < ApplicationJob
  def perform(customer_id, person_id)
    customer = Customer.find(customer_id)
    SymmetricEncryption.with_cipher(customer.cipher) do
      # ...
    end
  end
end
~~~

### Next => [Key Rotation](key_rotation.html)
