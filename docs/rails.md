---
layout: default
redirect_from:
  - /frameworks.html
---

## Rails
{:.no_toc}

**Contents**

* TOC
{:toc}

Encrypted attributes are declared with the
[Active Record Attributes API](https://api.rubyonrails.org/classes/ActiveRecord/Attributes/ClassMethods.html),
using the `:encrypted` type this gem registers.

New to the library? Work through the [Guide](guide.html) first; this page covers the Rails specifics
in depth.

## Declaring an encrypted attribute

~~~ruby
class Person < ActiveRecord::Base
  attribute :name, :encrypted
end
~~~

The column name matches the attribute name. There is no `encrypted_` prefix.

### The column type

The column is `string`, or `text` when the value can be long. It is never the type the attribute
returns, because what is stored is always base64 encoded ciphertext:

~~~ruby
create_table :people, force: true do |t|
  t.string :name
  t.string :age       # An :integer attribute, but a string column.
  t.text   :address   # Long values.
end
~~~

Encryption also makes values longer: base64 expands by a third, plus a header of 6 bytes, plus the
initialization vector when one is stored. Size the column accordingly.

### Options

~~~ruby
class Person < ActiveRecord::Base
  attribute :name,    :encrypted, random_iv: false
  attribute :age,     :encrypted, type: :integer
  attribute :address, :encrypted, compress: true
  attribute :api_key, :encrypted, version: 3
end
~~~

* `type:` — what the attribute returns in Ruby. See the table in the [Guide](guide.html#step-4-choose-the-type).
  Default: `:string`
* `random_iv:` — a new random initialization vector on every write. Default: `true`. Set to `false`
  only when the column must be searchable.
* `compress:` — compress before encrypting. Worth it only for large values. Default: `false`
* `version:` — encrypt with a specific configured cipher rather than the primary one. Default: the
  primary cipher.

## Type casting

The value is cast when it is assigned, using the same rules Active Record applies to an unencrypted
attribute of that type:

~~~ruby
person.age = "124"
person.age
# => 124
~~~

This is deliberate: an encrypted attribute should be indistinguishable from an unencrypted one apart
from the encryption. It also means the surprising parts of Active Record casting are inherited:

* A blank string becomes `nil` for every type other than `:string`.
* A value that cannot be cast is **not rejected**. It becomes `0` for `:integer` and `:float`, `nil`
  for `:date`, `:datetime` and `:time`, and `true` for `:boolean`.

Casting never raises. Reject bad input with a validation, exactly as for any other attribute:

~~~ruby
class Person < ActiveRecord::Base
  attribute :age, :encrypted, type: :integer

  validates :age, numericality: {allow_nil: true}
end
~~~

The validation reports on the value that was assigned rather than the cast one, since the assigned
value is still available in `age_before_type_cast`.

`:json` and `:yaml` values are left exactly as assigned, which is what Active Record's own `:json`
type does. They are serialized when the record is saved and parsed when it is read back.

### Multiparameter assignment

A `:date`, `:datetime` or `:time` attribute can be assigned from a form built with `date_select`,
`datetime_select` or `time_select`, which submit one field per part:

~~~erb
<%= form.date_select :date_of_birth %>
~~~

Active Record collects `date_of_birth(1i)`, `date_of_birth(2i)` and `date_of_birth(3i)` and assigns
them in one go. They are cast exactly as for an unencrypted date column: parts that were not
submitted take the same defaults, an incomplete date becomes `nil`, and validations report on the cast
value rather than on `date_of_birth_before_type_cast`.

## Keeping values out of logs

An encrypted attribute returns its decrypted value, so anything that renders the whole record would
otherwise write that value out. Encrypted attributes are added to the model's
[filter_attributes](https://api.rubyonrails.org/classes/ActiveRecord/Core/ClassMethods.html#method-i-filter_attributes)
as they are declared, so `inspect`, `attribute_for_inspect`, and the request parameters in the Rails
logs show `[FILTERED]`:

~~~ruby
class Person < ActiveRecord::Base
  attribute :ssn, :encrypted
end

Rails.logger.info(person)
# => #<Person id: 1, name: "Jack", ssn: [FILTERED]>
~~~

This is what Active Record's own `encrypts` does. To turn it off, set it before the models are
loaded, since the filter is applied when the attribute is declared:

~~~ruby
# config/application.rb
config.symmetric_encryption.filter_encrypted_attributes = false
~~~

### One caveat about load order

Adding to a model's `filter_attributes` takes a copy of the list it inherits from
`ActiveRecord::Base`, which is where Rails puts the application's `config.filter_parameters`. A model
loaded before Rails has set those, from a gem's railtie or from an initializer that references the
model, therefore filters its encrypted attributes but not the attributes named in
`config.filter_parameters`. Set `filter_attributes` in the model itself when it is loaded that early:

~~~ruby
class Person < ActiveRecord::Base
  self.filter_attributes += %i[password]

  attribute :ssn, :encrypted
end
~~~

Models loaded the usual way, eager loaded on boot or autoloaded on first use, are unaffected. Active
Record's own `encrypts` copies the list at declaration time in exactly the same way.

## Rendering JSON

Filtering covers `inspect` and the logs, which is as far as Active Record itself goes. It does not
cover `as_json`, so an encrypted attribute is rendered in full by `render json:`:

~~~ruby
Person.create(name: "Jack", ssn: "top_secret").as_json
# => {"id" => 1, "name" => "Jack", "ssn" => "top_secret"}
~~~

That is deliberate: an encrypted attribute meant to be part of an API response has to keep working.
When the value should never reach a response, include `ExcludeFromJson`:

~~~ruby
class Person < ActiveRecord::Base
  include SymmetricEncryption::ActiveRecord::ExcludeFromJson

  attribute :ssn, :encrypted
end

Person.create(name: "Jack", ssn: "top_secret").as_json
# => {"id" => 1, "name" => "Jack"}
~~~

Every encrypted attribute in that model is then left out of `as_json`, `to_json` and
`serializable_hash`, including when `as_json(only: %i[ssn])` asks for it. Rendering one becomes a
deliberate act, by asking for it by name:

~~~ruby
person.as_json(methods: :ssn)
# => {"id" => 1, "name" => "Jack", "ssn" => "top_secret"}
~~~

Reading the attribute is unaffected, as are `attributes` and anything else that does not go through
`serializable_hash`.

## Validations

To ensure a value is encrypted before it is saved, use the bundled validator. This is only needed when
assigning an encrypted value to a column directly, since an attribute declared with the `:encrypted`
type is always encrypted on assignment:

~~~ruby
class Person < ActiveRecord::Base
  validates :encrypted_name, symmetric_encryption: true
end
~~~

## Encrypting an existing column

Declaring an attribute as `:encrypted` over a column that is not `string` or `text` fails when the
record is saved, because the encrypted value is a string:

~~~ruby
create_table :people, force: true do |t|
  t.integer :age
end

class Person < ActiveRecord::Base
  attribute :age, :encrypted, type: :integer
end

Person.create!(age: 2019)
# => PG::InvalidTextRepresentation: ERROR: invalid input syntax for integer: "QEVuQwJAEABHjHWXKblm..."
~~~

MySQL raises a similar error in strict mode, and quietly stores a zero when it is not. SQLite accepts
the value without complaint because of its dynamic typing, so a test suite running on SQLite will not
report this.

Changing the column type to `string` is not enough on its own: the values already in the column are
unencrypted, and reading one back through the encrypted attribute raises
`OpenSSL::Cipher::CipherError`. Encrypt them as part of the migration:

~~~ruby
class EncryptPersonAge < ActiveRecord::Migration[8.0]
  # A local model, so that the migration does not depend on how `Person` declares its attributes.
  class MigratedPerson < ActiveRecord::Base
    self.table_name = "people"
  end

  def up
    add_column :people, :encrypted_age, :string
    MigratedPerson.reset_column_information

    MigratedPerson.find_each do |person|
      person.update_column(:encrypted_age, SymmetricEncryption.encrypt(person.age))
    end

    remove_column :people, :age
    rename_column :people, :encrypted_age, :age
  end
end
~~~

`nil` values are left as `nil`, since `SymmetricEncryption.encrypt` returns `nil` for them. Add
`attribute :age, :encrypted, type: :integer` to the model only once the migration has run, since the
model reads the column as an encrypted value from that point on.

## Do not encrypt primary keys or foreign keys

An `id`, primary key, or foreign key column must not be declared `:encrypted`. Active Record builds
association queries from the encrypted value, so the query looks for the encrypted id rather than the
id itself:

~~~ruby
class Request < ActiveRecord::Base
  belongs_to :organisation
  attribute :organisation_id, :encrypted, type: :integer
end

organisation.requests.count
# SELECT COUNT(*) FROM "requests" WHERE "requests"."organisation_id" = $1
#   [["organisation_id", "QEVuQwJAEAADf7A6+JiS1XNImGA6PldIrRSddbiZiz1NiSxw2KikLA=="]]
~~~

Against the `integer` column a foreign key normally has, PostgreSQL rejects that value with
`PG::InvalidTextRepresentation`. After the column has been changed to a `string` the query is
accepted, but with the default `random_iv: true` it matches nothing, since the id encrypts to a
different value every time.

Adding `random_iv: false` makes `belongs_to` and `has_many` work, because Active Record passes the
value through the attribute type in both directions, but joins still return nothing:

~~~ruby
Organisation.joins(:requests).count
# => 0
~~~

The join compares `requests.organisation_id` against `organisations.id` in the database, where the
encrypted value on one side and the id on the other can never match. Neither can a foreign key
constraint, an index shared with an unencrypted column, or any query written in SQL.

Encrypt the attributes that hold personal data, and leave the columns that identify the row alone.

## Next steps

* [Migrating](migrating.html): from `attr_encrypted`, and to Active Record encryption.
* [Key Rotation](key_rotation.html): introducing a new key without downtime.
* [Mongoid](mongoid.html): the equivalent for Mongoid documents.
* [Security](security.html): authenticated encryption and PCI compliance.
