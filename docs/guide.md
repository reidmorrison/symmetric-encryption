---
layout: default
---

## Guide
{:.no_toc}

**Contents**

* TOC
{:toc}

This guide builds up from encrypting a single string to encrypting model attributes, configuration
file passwords, and whole files. Each step assumes the ones before it, so you can read it top to
bottom, or jump to the part you need.

Every example is runnable. Steps 1 and 2 need nothing but the gem installed.

## Step 1: Encrypt your first value

You do not need a configuration file to try the library. Set a cipher by hand with a throwaway key:

~~~ruby
require "symmetric_encryption"

SymmetricEncryption.cipher = SymmetricEncryption::Cipher.new(
  key:         "1234567890ABCDEF",
  iv:          "1234567890ABCDEF",
  cipher_name: "aes-128-cbc"
)
~~~

Now encrypt and decrypt:

~~~ruby
encrypted = SymmetricEncryption.encrypt("Hello World")
# => "QEVuQwAANIuPIXv/ii1IP1dF6T0NpQ=="

SymmetricEncryption.decrypt(encrypted)
# => "Hello World"
~~~

The result is base64 text, safe to put in a database column, a YAML file, or an HTTP header.

You can ask whether a value came from this library. It reads the header rather than attempting to
decrypt, so it is cheap and does not need the right key:

~~~ruby
SymmetricEncryption.encrypted?(encrypted)
# => true

SymmetricEncryption.encrypted?("Hello World")
# => false
~~~

`nil` and `""` pass through both methods untouched, so you never have to guard against them:

~~~ruby
SymmetricEncryption.encrypt(nil)
# => nil
SymmetricEncryption.encrypt("")
# => ""
~~~

That key is published here, so it protects nothing. Step 2 replaces it.

## Step 2: Generate real keys

Generate a configuration file and a key for every environment:

~~~
symmetric-encryption --generate --app-name my_app
~~~

~~~
New configuration file created at: config/symmetric-encryption.yml
~~~

Two kinds of file come out of this, and keeping them apart is the entire point:

* `config/symmetric-encryption.yml` belongs **in source control**. It names the ciphers and says
  where their keys live. On its own it decrypts nothing.
* The key files under `~/.symmetric-encryption` **never go into source control**. Deploy each
  environment's key only to that environment's servers.

In Rails, that is all the setup there is. The railtie loads the configuration during boot, early
enough that `database.yml` can itself contain an encrypted password.

Outside Rails, load it yourself:

~~~ruby
SymmetricEncryption.load!("config/symmetric-encryption.yml", "production")
~~~

See [Configuration](configuration.html) for the keystores, including AWS KMS and Google Cloud KMS.

## Step 3: Encrypt a model attribute

Add a `string` column. It holds base64 text, so it is a string whatever the attribute's type:

~~~ruby
class AddSsnToPeople < ActiveRecord::Migration[8.0]
  def change
    add_column :people, :ssn, :string
  end
end
~~~

Declare the attribute with the `:encrypted` type:

~~~ruby
class Person < ActiveRecord::Base
  attribute :ssn, :encrypted
end
~~~

It now behaves like any other attribute:

~~~ruby
person = Person.create!(name: "Jack", ssn: "123456789")
person.ssn
# => "123456789"

person.reload.ssn
# => "123456789"
~~~

The database holds only ciphertext:

~~~sql
SELECT name, ssn FROM people;
-- Jack | QEVuQwJAEACOYREfF1cAXU0B8Xre7bISBCV415agBWeiX6cF1boT2g==
~~~

Using Mongoid instead? See [Mongoid](mongoid.html), which uses a `field ... encrypted: true` option
rather than an attribute type.

## Step 4: Choose the type

An encrypted attribute is stored as text, but it does not have to *be* text. Declare a type and the
value is cast on the way in and on the way out:

~~~ruby
class Person < ActiveRecord::Base
  attribute :ssn,           :encrypted
  attribute :age,           :encrypted, type: :integer
  attribute :date_of_birth, :encrypted, type: :date
end
~~~

~~~ruby
person = Person.create!(ssn: "123456789", age: 21, date_of_birth: "1998-03-04")

person.age
# => 21               (Integer, not "21")
person.date_of_birth
# => Wed, 04 Mar 1998 (Date)
~~~

The available types are:

| Type | Ruby class |
|---|---|
| `:string` (default) | `String` |
| `:integer` | `Integer` |
| `:float` | `Float` |
| `:decimal` | `BigDecimal` |
| `:datetime` | `DateTime` |
| `:time` | `Time` |
| `:date` | `Date` |
| `:boolean` | `TrueClass` or `FalseClass` |
| `:json` | Serialized with JSON, for hashes and arrays |
| `:yaml` | Serialized with YAML, for hashes and arrays |

Casting deliberately matches Active Record exactly, so an encrypted attribute is indistinguishable
from an unencrypted one apart from the encryption. That includes the parts that surprise people:

~~~ruby
Person.new(age: "abc").age
# => 0     Exactly what ActiveModel::Type::Integer does. It does not raise, and it is not nil.

Person.new(age: "").age
# => nil   A blank string is nil for every type except :string.
~~~

Casting never raises. To reject input that could not be cast, validate against
`*_before_type_cast`, which is how you would do it for an unencrypted attribute.

## Step 5: Decide whether the value must be searchable

By default each write produces a *different* ciphertext for the same input, because a new random
initialization vector is generated every time. That is what you want: it stops an attacker learning
that two rows hold the same value.

~~~ruby
a = Person.create!(ssn: "123456789")
b = Person.create!(ssn: "123456789")
# The two rows hold completely different ciphertext.
~~~

The cost is that you cannot look the value up, because you cannot reproduce the ciphertext to search
for:

~~~ruby
Person.where(ssn: "123456789")   # Finds nothing. Never will.
~~~

When a column has to be searchable, turn the random IV off. The same input then always encrypts to
the same output, and equality lookups work:

~~~ruby
class Person < ActiveRecord::Base
  attribute :ssn, :encrypted, random_iv: false
end

Person.where(ssn: "123456789").first   # Works.
~~~

Understand the trade: anyone who can read the table can now see which rows share a value, even
without the key. Use `random_iv: false` only on columns you genuinely query, and prefer an
authenticated cipher when you do. See [Security](security.html).

Only equality works. `LIKE`, ranges, and ordering operate on ciphertext and are meaningless.

## Step 6: Keep decrypted values out of logs and JSON

Encrypting the column does nothing if the decrypted value is written to the log a moment later.

**Logs and `inspect` are handled for you.** Every attribute declared `:encrypted` is added to the
model's `filter_attributes` when it is declared:

~~~ruby
person.inspect
# => #<Person id: 1, name: "Jack", ssn: [FILTERED], age: [FILTERED]>

Person.filter_attributes
# => [:ssn, :age]
~~~

This also adds `"person.ssn"` to the application's `config.filter_parameters`, so the value is
filtered out of request parameters in the logs too.

**JSON is not, and that is deliberate.** `as_json` still returns decrypted values, because an
encrypted attribute that is deliberately rendered into an API response has to keep working:

~~~ruby
person.as_json
# => {"id" => 1, "name" => "Jack", "ssn" => "123456789"}
~~~

To exclude them, include the module:

~~~ruby
class Person < ActiveRecord::Base
  include SymmetricEncryption::ActiveRecord::ExcludeFromJson

  attribute :ssn, :encrypted
end
~~~

~~~ruby
person.as_json
# => {"id" => 1, "name" => "Jack"}
~~~

Rendering one then takes asking for it by name, which is hard to do by accident:

~~~ruby
person.as_json(methods: :ssn)
# => {"id" => 1, "name" => "Jack", "ssn" => "123456789"}
~~~

See [Rails](rails.html) for both in detail.

## Step 7: Encrypt a password in a configuration file

Encrypt the value from the command line:

~~~
symmetric-encryption --encrypt --prompt
~~~

You are prompted twice, and the encrypted value is printed. Paste it into the configuration file:

~~~yaml
production:
  adapter:  postgresql
  database: my_app_production
  username: my_app
  password: <%= SymmetricEncryption.try_decrypt("QEVuQwJAEACOYREfF1cAXU0B8Xre7bISBCV415agBWeiX6cF1boT2g==") %>
~~~

`try_decrypt` rather than `decrypt`: it returns `nil` instead of raising when the value cannot be
decrypted, so a developer machine without the production key can still load the file.

This works in `database.yml` because the railtie loads the configuration in `before_configuration`,
deliberately earlier than Active Record.

When you rotate keys, re-encrypt every value already sitting in your configuration files:

~~~
symmetric-encryption --re-encrypt "**/*.yml"
~~~

## Step 8: Encrypt a file

`Writer` and `Reader` behave like Ruby's `IO`, encrypting and decrypting as data flows through them,
so file size is not a constraint:

~~~ruby
SymmetricEncryption::Writer.open("secure.enc") do |file|
  file.write("Hello World\n")
  file.write("Second line\n")
end
~~~

~~~ruby
SymmetricEncryption::Reader.open("secure.enc") do |file|
  file.each_line { |line| puts line }
end
# Hello World
# Second line
~~~

Or encrypt a whole file in one call:

~~~ruby
SymmetricEncryption::Writer.encrypt(source: "plain.txt", target: "secure.enc")
~~~

Each file gets its own random key, encrypted with your configured key and stored in the file's
header, so the file is self-describing. Compression is on by default for file names that are not
already compressed.

See [Files](files.html) for streams, CSV, seeking, and tamper detection.

## Going further

**Detect tampering.** `aes-256-cbc` will decrypt a modified value and return garbage. `aes-256-gcm`
refuses. See [Security](security.html).

**Rotate keys** without downtime, and read data encrypted by keys you retired years ago. See
[Key Rotation](key_rotation.html).

**Use a different key for some of your data**, for example a key per customer held in your database
rather than in `symmetric-encryption.yml`:

~~~ruby
SymmetricEncryption.with_cipher(cipher_for(customer)) do
  person.save!
end
~~~

See [Key Rotation](key_rotation.html#a-key-per-customer).

**Encrypt one attribute with a different key** from everything else:

~~~ruby
attribute :api_key, :encrypted, version: 3
~~~

## Next steps

* [Configuration](configuration.html): the configuration file, and every keystore.
* [Rails](rails.html): validations, filtering, JSON, and migrations in depth.
* [Files](files.html): streams, CSV, and large file handling.
* [Command Line](cli.html): every `symmetric-encryption` option.
* [API](api.html): the full method reference.
