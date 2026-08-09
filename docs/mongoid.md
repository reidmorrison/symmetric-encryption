---
layout: default
---

## Mongoid
{:.no_toc}

**Contents**

* TOC
{:toc}

Symmetric Encryption adds an `encrypted:` option to Mongoid fields. Declaring it generates a getter,
a setter, and a `_changed?` method for the decrypted value, so the document is worked with in the
clear while MongoDB only ever holds ciphertext.

Encrypting Active Record attributes instead? See [Rails](rails.html).

## Step 1: Encrypt a field

The field holds the encrypted value, so it is declared `type: String` and named with an
`encrypted_` prefix:

~~~ruby
class User
  include Mongoid::Document

  field :name,                             type: String
  field :encrypted_bank_account_number,    type: String, encrypted: true
end
~~~

Symmetric Encryption generates accessors for the name with the prefix removed:

~~~ruby
user = User.create!(name: "Jack", bank_account_number: "12345")

user.bank_account_number
# => "12345"
~~~

MongoDB holds only the encrypted value:

~~~javascript
{
  "name" : "Jack",
  "encrypted_bank_account_number" : "QEVuQwJAEACOYREfF1cAXU0B8Xre7bISBCV415agBWeiX6cF1boT2g=="
}
~~~

Reading the field is what decrypts it. A document that is loaded but never asked for the decrypted
value never decrypts anything, and the decrypted value is cached until the encrypted one changes.

### Naming the accessors yourself

The field name must start with `encrypted_`, or `:decrypt_as` must say what to call the accessors:

~~~ruby
field :ssn_encrypted, type: String, encrypted: {decrypt_as: :ssn}
~~~

Without either, declaring the field raises an `ArgumentError`.

## Step 2: Pass options

`encrypted: true` accepts the defaults. Supply a Hash to change them:

~~~ruby
class User
  include Mongoid::Document

  field :name,                             type: String
  field :encrypted_bank_account_number,    type: String, encrypted: true
  field :encrypted_social_security_number, type: String, encrypted: true
  field :encrypted_life_history,           type: String, encrypted: {compress: true, random_iv: true}
  field :encrypted_age,                    type: String, encrypted: {type: :integer}
end
~~~

* `type:` — what the decrypted value is coerced to. See the table in the
  [Guide](guide.html#step-4-choose-the-type). Default: `:string`
* `random_iv:` — a new random initialization vector on every write. Default: `false`
* `compress:` — compress before encrypting. Worth it only for large values. Default: `false`
* `version:` — encrypt with a specific configured cipher rather than the primary one.
* `decrypt_as:` — the name to give the generated accessors.

Note that `random_iv` defaults to **`false`** here, the opposite of the Active Record attribute type.
Turn it on for any field you do not query:

~~~ruby
field :encrypted_life_history, type: String, encrypted: {random_iv: true}
~~~

The field is stored as a `String` whatever `type:` says, because the encrypted value is always text.
`type:` only decides what the getter coerces the decrypted value back into, so `user.age` returns an
`Integer`.

## Step 3: Query an encrypted field

Only the encrypted field exists in MongoDB, so queries use the encrypted name and the encrypted
value:

~~~ruby
user = User.where(encrypted_bank_account_number: SymmetricEncryption.encrypt("12345")).first
~~~

This works only when the field was encrypted with `random_iv: false`, the default here. With a random
initialization vector the same input encrypts to a different value every time, so nothing matches.

Querying by the decrypted name finds nothing, and does not raise:

~~~ruby
User.where(bank_account_number: "12345").first
# => nil, always. There is no such field in MongoDB.
~~~

Only equality works. Ranges, ordering, and regular expressions operate on ciphertext and are
meaningless.

## Validations

To ensure a value is encrypted before it is saved:

~~~ruby
class User
  include Mongoid::Document

  field :encrypted_ssn, type: String, encrypted: true

  validates :encrypted_ssn, symmetric_encryption: true
end
~~~

## Standalone Mongoid

Outside Rails, initialize both libraries yourself:

~~~ruby
require "mongoid"
require "symmetric-encryption"

Mongoid.logger = Logger.new($stdout)
Mongoid.load!("config/mongoid.yml")

SymmetricEncryption.load!("config/symmetric-encryption.yml", "production")
~~~

## Next steps

* [Guide](guide.html): the library, one step at a time.
* [Configuration](configuration.html): the configuration file and the keystores.
* [Security](security.html): authenticated encryption and PCI compliance.
