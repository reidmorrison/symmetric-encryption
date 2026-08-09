---
layout: default
---

## Migrating to Active Record encryption

Rails 7 added [Active Record encryption](https://guides.rubyonrails.org/active_record_encryption.html).
For a Rails application whose encrypted data is nothing but Active Record attributes, it is the
better choice: it is built in, and it is maintained by the Rails team.

This page is for moving those attributes over without re-encrypting the database first, and
without downtime. Values already in the database keep being read by Symmetric Encryption, while
every value that is written from then on is encrypted by Active Record.

If the application also encrypts Mongoid fields, files, or passwords in configuration files, keep
this gem for those. Active Record encryption does not cover them. See
[the home page](index.html) for what is and is not worth migrating.

### 1. Configure Active Record encryption

~~~bash
bin/rails db:encryption:init
~~~

Add the generated keys to the Rails credentials, as the Rails guide describes. This is entirely
separate from `symmetric-encryption.yml`. Both sets of keys are in use during the migration.

### 2. Declare the attributes

Replace the `attribute ... :encrypted` declaration with `encrypts`, and name this gem's encryptor
as a previous encryption scheme:

~~~ruby
class User < ApplicationRecord
  # Before
  # attribute :ssn, :encrypted

  encrypts :ssn, previous: [{encryptor: SymmetricEncryption::ActiveRecord::RailsEncryptor.new}]
end
~~~

Active Record decrypts every value with its own encryptor first, and falls back to the previous
schemes when that fails. Values encrypted by this gem are read by the previous scheme. Values
encrypted by Active Record are read by Active Record. Both work from the first deploy.

`SymmetricEncryption.load!`, or the Railtie in a Rails application, still has to run, since the
keys are still read from `symmetric-encryption.yml`.

### 3. Attributes that are queried

An attribute declared `random_iv: false` so that it can be used in a `where` clause becomes a
deterministic attribute, and it needs one extra option:

~~~ruby
class User < ApplicationRecord
  # Before
  # attribute :api_key, :encrypted, random_iv: false

  encrypts :api_key,
           deterministic: {fixed: false},
           previous:      [{encryptor: SymmetricEncryption::ActiveRecord::RailsEncryptor.new}]
end
~~~

`deterministic: true` on its own encrypts new values with the _oldest_ scheme, which is this
gem's encryptor, and that encryptor refuses to write. `fixed: false` tells Active Record to
encrypt with the current scheme instead. Without it, saving the record raises:

~~~
ActiveRecord::Encryption::Errors::Encryption: SymmetricEncryption::ActiveRecord::RailsEncryptor
only decrypts, ...
~~~

Note that queries only find values that Active Record encrypted. A row still holding a value that
this gem encrypted will not match, so finish step 4 before relying on the query.

### 4. Migrate the data

Values move over as records are saved. To migrate the rest, re-save them:

~~~ruby
User.find_each { |user| user.update_column(:ssn, user.ssn) }
~~~

`update_column` writes through the attribute type, so the value is decrypted by Symmetric
Encryption and written back encrypted by Active Record, without running validations or callbacks.

`update!(ssn: user.ssn)` does _not_ work. Assigning the value it already has is not a change, so
Active Record writes nothing and the row is left as it was. Use `update_column` as above, or
`user.ssn_will_change!` followed by `user.save!` when validations and callbacks should run.

Check that nothing is left before moving on:

~~~ruby
User.find_each.count { |user| SymmetricEncryption.encrypted?(user.ssn_before_type_cast) }
# => 0
~~~

### 5. Remove the previous scheme

Once no value in the database was encrypted by this gem, drop the `previous:` option:

~~~ruby
class User < ApplicationRecord
  encrypts :ssn
end
~~~

If nothing else in the application uses Symmetric Encryption, remove the gem and
`symmetric-encryption.yml`. Keep the keys somewhere safe until there is a restored backup that
proves nothing still needs them.

### Notes

* The encryptor only decrypts. It never writes a value in this gem's format, so a partly migrated
  application cannot silently go backwards.
* Only ciphers using one of the base64 encodings are supported, which is the default. A cipher
  configured with `encoding: :none` returns binary data, which does not belong in the text column
  Active Record encryption expects.
* Active Record encryption cannot rotate its deterministic key, while this gem can. If an
  attribute has to be both queryable and re-keyed, that is a reason not to migrate it. See
  [Authenticated Encryption](authenticated_encryption.html).

### Next => [PCI Compliance](pci_compliance.html)
