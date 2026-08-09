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

Give each key its own version in the configuration file, and name the version when encrypting:

~~~ruby
encrypted = SymmetricEncryption.encrypt("Hello World", version: 3)

SymmetricEncryption.decrypt(encrypted)
# => "Hello World"
~~~

Decryption needs nothing extra. The version is in the header, so the right cipher is chosen
automatically.

Files and streams take the same option:

~~~ruby
SymmetricEncryption::Writer.open("archive.enc", version: 3) { |file| file.write(data) }
~~~

Active Record attributes and Mongoid fields take it when they are declared:

~~~ruby
class Person < ActiveRecord::Base
  attribute :ssn,     :encrypted
  attribute :api_key, :encrypted, version: 3
end

class Person
  include Mongoid::Document

  field :encrypted_ssn,     type: String, encrypted: true
  field :encrypted_api_key, type: String, encrypted: {version: 3}
end
~~~

Changing the version of an attribute leaves values that were already written readable, since each
value records the version it was encrypted with. New values are written with the new key, so the
data moves over as records are saved.

Two things to know before relying on this:

* The command line interface treats every version as a rotation of the same key.
  `--activate-key` moves the highest version to the top, and `--cleanup-keys` removes everything
  except the highest. `--cleanup-keys` names the versions it is about to remove and asks first,
  but `--activate-key` will still reorder a configuration file that holds keys for more than one
  purpose, which changes which key new data is encrypted with.
* All of the ciphers have to use a compatible `encoding`, since a value is decoded before its
  header is read. `:base64` and `:base64strict` work together, and mixing anything else is
  refused when the configuration file is loaded.

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
