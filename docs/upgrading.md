---
layout: default
---

## Upgrading
{:.no_toc}

**Contents**

* TOC
{:toc}

What changes between major versions, and what to do about it. Each section covers upgrading *to*
that version, so read from your current version downwards.

Data encrypted by any earlier version stays readable throughout. The encrypted value format has not
changed, and backward compatibility with it is a hard requirement.

Moving *away* from this gem to Active Record encryption is a different job: see
[Rails](rails.html#migrating-to-active-record-encryption).

## Upgrading to v5

### Minimum versions

Ruby 3.2 and Rails 7.2. Earlier versions are end-of-life and are no longer tested.

### New configurations are generated with `aes-256-gcm`

`symmetric-encryption --generate` now writes `aes-256-gcm` instead of `aes-256-cbc`. `aes-256-cbc`
keeps data secret but cannot tell whether it has been changed; `aes-256-gcm` is authenticated, so
decryption fails rather than returning whatever the altered bytes decrypt to. See
[Security](security.html).

**Existing configuration files are unaffected.** They name their own `cipher_name`, and a cipher
entry that omits it still defaults to `aes-256-cbc`, so data already encrypted stays readable.
Nothing has to be done to upgrade.

To move an existing application over, add a new key with the new cipher and keep the old one as a
secondary, which is ordinary [key rotation](key_rotation.html):

~~~
symmetric-encryption --rotate-keys --cipher-name aes-256-gcm --environments production
~~~

Values encrypted with the old key keep being read, because the cipher version travels in each
value's header. Two things to know before switching:

* Encrypted values grow by roughly 30 bytes, since an authenticated value always carries a header
  and a 16 byte auth tag. Check any column whose length is tight.
* A value encrypted with `random_iv: false`, so that it can be queried, derives its initialization
  vector from the value itself rather than using the configured one. The same input still encrypts
  to the same output, so lookups keep working.

### `attr_encrypted` has been removed

It was already unusable under Rails 7, which defines its own conflicting `encrypted_attributes`
method. Replace each declaration with the equivalent `attribute` declaration. The options are
unchanged:

~~~ruby
# Before
class Person < ActiveRecord::Base
  attr_encrypted :name, random_iv: false
  attr_encrypted :age, random_iv: true, type: :integer
end

# After
class Person < ActiveRecord::Base
  attribute :name, :encrypted, random_iv: false
  attribute :age, :encrypted, type: :integer
end
~~~

Data encrypted by `attr_encrypted` is still readable, the encrypted value format is unchanged.

One thing to watch: `attr_encrypted` required the database column to be named `encrypted_name`,
whereas the attribute type uses a column with the same name as the attribute. Either rename the
columns in a migration, or declare the attributes against the existing column names.

Removed along with it: `encrypted_attributes`, `encrypted_keys`, `encrypted_columns`,
`encrypted_attribute?` and `encrypted_column?`.

### Encrypted attributes are cast when assigned

Previously an assigned value kept its original type until the record had been saved and reloaded:

~~~ruby
person.age = "124"
person.age
# Before: "124"
# After:  124
~~~

The declared type is now applied immediately, using Active Record's own casting rules, so an
encrypted attribute behaves like the equivalent unencrypted one. Two consequences worth checking
before upgrading:

* A blank string becomes `nil` for every type other than `:string`, so the column now holds `NULL`
  rather than an encrypted `""`.
* A value that cannot be cast no longer raises `Coercible::UnsupportedCoercion`. It becomes whatever
  Active Record would use: `0` for `:integer` (and `"12abc"` becomes `12`), `0.0` for `:float` and
  `:decimal`, `nil` for `:date`, `:datetime` and `:time`, and `true` for `:boolean`. Add
  `validates :age, numericality: true` to reject it, exactly as for an unencrypted attribute. The
  assigned value is still available in `age_before_type_cast`, which is what that validation reports
  on.

A `type:` that is not one of the supported types is now rejected with an `ArgumentError` naming the
valid ones when the attribute is declared, rather than failing later with a coercion error.

See [Rails](rails.html#type-casting) for the full casting rules.

### Encrypted attributes are filtered from logs

Attributes declared with the `:encrypted` type are added to the model's `filter_attributes` as they
are declared, so `inspect` and the Rails logs show `[FILTERED]` instead of the decrypted value. This
is what Active Record's own `encrypts` does.

Turn it off before the models are loaded if the previous behaviour is wanted:

~~~ruby
# config/application.rb
config.symmetric_encryption.filter_encrypted_attributes = false
~~~

`as_json` is deliberately not covered. See [Rails](rails.html#rendering-json).

### Google Cloud KMS requires `google-cloud-kms` v2

Update the dependency if you use that keystore.

## Upgrading to v4

### Keyword arguments

Version 4 adopted keyword arguments for optional arguments across the API.

This does *not* change:

~~~ruby
encrypted = SymmetricEncryption.encrypt("Hello World")
SymmetricEncryption.decrypt(encrypted)
~~~

These are not backward compatible:

~~~ruby
# Before
SymmetricEncryption.encrypt("Hello World", false, false, :date)
SymmetricEncryption.decrypt(encrypted, 2, :date)

# After
SymmetricEncryption.encrypt("Hello World", random_iv: false, compress: false, type: :date)
SymmetricEncryption.decrypt(encrypted, version: 2, type: :date)
~~~

Only the arguments that are needed have to be supplied:

~~~ruby
SymmetricEncryption.encrypt("Hello World", type: :date)
~~~

### Rake tasks replaced by a command line interface

Key generation and configuration are managed by the `symmetric-encryption` command:

~~~
symmetric-encryption --help
~~~

See [Command Line](cli.html).

### Configuration file changes

The configuration file is now modified in place rather than generated from templates, so that the
command line interface can generate new keys and update the file itself.

**Back up `symmetric-encryption.yml` before upgrading** if it is not already in version control.
This matters most for configurations with custom code, and for earlier Heroku configurations.

The defaults for `encoding` and `always_add_header` also changed. If they are not set explicitly,
set them to the old defaults *before* upgrading, then move to the new ones deliberately:

~~~yaml
# Prior defaults. Set these explicitly before upgrading if they are missing.
encoding:          :base64
always_add_header: false
~~~

~~~yaml
# New defaults.
encoding:          :base64strict
always_add_header: true
~~~

`always_add_header: true` is strongly recommended: the header is what carries the cipher version,
and therefore what makes [key rotation](key_rotation.html) possible.

## Upgrading to v3

* `SymmetricEncryption.decrypt` no longer rotates through every configured key when one fails to
  decrypt. In a small but significant number of cases it was possible to decrypt data with the wrong
  key: the result was garbage, but it was returned as a string rather than raising. Supply
  `SymmetricEncryption.select_cipher` to choose the cipher yourself when an encrypted value has no
  header and several ciphers are configured.
* The configuration file format prior to v1 is no longer supported.
* Encryption keys can be set from environment variables, through the new `:encrypted_key` and
  `:encrypted_iv` options. This also supports reading them from other sources, such as LDAP or a
  central directory service.
* `Cipher.parse_magic_header!` returns a Struct rather than an Array.

## Next steps

* [Configuration](configuration.html): the configuration file and the keystores.
* [Key Rotation](key_rotation.html): introducing a new key without downtime.
* [Rails](rails.html): encrypted Active Record attributes, and migrating to Active Record encryption.
