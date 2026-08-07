---
layout: default
---

## Supported Frameworks

The following frameworks are directly supported by Symmetric Encryption

* Ruby on Rails
* Mongoid

### Active Record

Encrypted attributes are declared using the
[ActiveRecord Attributes API](https://api.rubyonrails.org/classes/ActiveRecord/Attributes/ClassMethods.html).

Example: Model `Person` has an encrypted attribute called `name` of type string.

~~~ruby
class Person < ActiveRecord::Base
  attribute :name, :encrypted
end
~~~

In the database migration, the `name` column should be defined as type `string` and should be large enough to hold
the base64 encoded value after encryption. If the text can be very long, use the type `text`.

~~~ruby
create_table :people, force: true do |t|
  t.string :name
  t.string :age
  t.text :address
end
~~~ 

By default when defining an attribute it will be encrypted with a new, random, initialization vectore (IV).
The IV is also stored along with the encrypted value, which makes it a little larger.

The default of `random_iv: true` is highly recommended for security reasons. However, we would never be able to
perform a query using that field, since the random IV causes the value to change every time the same data is
encrypted.

As a result, the following query would never get a match:

~~~ruby
Person.where(name: "Jack").count
~~~

For these columns, it is necessary to add the option `random_iv: true`:

~~~ruby
class Person < ActiveRecord::Base
  attribute :name, :encrypted, random_iv: false
end
~~~

Since the value stored in the database is always an encrypted string, the ultimate type of the
attribute needs to be supplied: 

* :string    => String
* :integer   => Integer
* :float     => Float
* :decimal   => BigDecimal
* :datetime  => DateTime
* :time      => Time
* :date      => Date
* :boolean   => true or false
* :json      => Uses JSON serialization, useful for hashes and arrays
* :yaml      => Uses YAML serialization, useful for hashes and arrays

Example: The encrypted attribute `age` can be specified as an integer:

~~~ruby
class Person < ActiveRecord::Base
  attribute :name, :encrypted, random_iv: false
  attribute :age,  :encrypted, type: :integer
  attribute :address, :encrypted, compress: true
end
~~~

`type:` is the type the attribute returns in Ruby, not the type of the database column. The column is
always `string` or `text`, whatever the declared type, since the value stored in the database is always
the base64 encoded encrypted string. In the example above, `age` is an `Integer` in Ruby and a
`t.string` column in the migration.

For larger encrypted attributes it is also worthwhile to compress the value after it has been encrypted,
by adding the option:
`compress: true`

#### Type casting

The value is cast to the declared type as soon as it is assigned, using the same rules Active Record
applies to an unencrypted attribute of that type:

~~~ruby
person.age = "124"
person.age
# => 124
~~~

That means a blank string becomes `nil` for every type other than `:string`, and a value that cannot be
cast is not rejected: it becomes `0` for `:integer` and `:float`, `nil` for `:date`, `:datetime` and
`:time`, and `true` for `:boolean`. Reject it the same way as for any other attribute, with a validation:

~~~ruby
class Person < ActiveRecord::Base
  attribute :age, :encrypted, type: :integer

  validates :age, numericality: {allow_nil: true}
end
~~~

The validation reports on the value that was assigned, not on the cast one, since the assigned value is
still available in `age_before_type_cast`.

`:json` and `:yaml` values are left exactly as they were assigned, which is also what Active Record's own
`:json` type does. They are serialized when the record is saved, and parsed when it is read back.

#### Note

The column name in the database matches the name of the attribute in the model.

#### Encrypting an existing column

Declaring an attribute as `:encrypted` over a column that is not a `string` or `text` column fails when
the record is saved, because the encrypted value is a string:

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
the value without complaint, because of its dynamic typing, so a test suite running on SQLite will not
report this.

Changing the type of the column to `string` is not enough on its own: the values already in the column
are unencrypted, and reading one back through the encrypted attribute raises
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

#### Upgrading from attr_encrypted

`attr_encrypted` was removed in Symmetric Encryption v5. It was already unusable under Rails 7,
which defines its own conflicting `encrypted_attributes` method.

Replace each `attr_encrypted` declaration with the equivalent `attribute` declaration. The options
are unchanged:

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

Note that `attr_encrypted` required the database column to be named `encrypted_name`, whereas the
attribute type uses a column with the same name as the attribute. Rename the columns in a migration,
or keep the existing column names and declare the attributes against those names.

Values encrypted by `attr_encrypted` are read without any conversion, since the encrypted value
format is unchanged.

#### Validations

To ensure that a value is encrypted before it is saved, a validation can be used. This is only needed
when assigning an encrypted value to a column directly, since an attribute declared with the
`:encrypted` type is always encrypted on assignment.

~~~ruby
class Person < ActiveRecord::Base
  validates :encrypted_name, symmetric_encryption: true
end
~~~

### Mongoid

To encrypt a field in a Mongoid document, just add "encrypted: true" at the end
of the field specifier. The field name must currently begin with "encrypted_"

~~~ruby
# User model in Mongoid
class User
  include Mongoid::Document

  field :name,                             type: String
  field :encrypted_bank_account_number,    type: String,  encrypted: true
  field :encrypted_social_security_number, type: String,  encrypted: true
  field :encrypted_life_history,           type: String,  encrypted: {compress: true, random_iv: true}

  # Encrypted fields are _always_ stored in Mongo as a String
  # To get the result back as an Integer, Symmetric Encryption can do the
  # necessary conversions by specifying the internal type as an option
  # to :encrypted
  # #see SymmetricEncryption::COERCION_TYPES for full list of types
  field :encrypted_age,                    type: String, encrypted: {type: :integer}
end

# Create a new user document
User.create(bank_account_number: '12345')

# When finding a document, always use the encrypted form of the field name
user = User.where(encrypted_bank_account_number: SymmetricEncryption.encrypt('12345')).first

# Fields can be accessed using their unencrypted names
puts user.bank_account_number
~~~

### Next => [Configuration](configuration.html)
