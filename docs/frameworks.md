---
layout: default
---

## Supported Frameworks

The following frameworks are directly supported by Symmetric Encryption

* Ruby on Rails
* Mongoid

### Rails 5

As of Symmetric Encryption v4.3, when using Rails v5 and above the recommended approach is to use the new 
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

For larger encrypted attributes it is also worthwhile to compress the value after it has been encrypted,
by adding the option:
`compress: true`

#### Note

The column name in the database matches the name of the attribute in the model. 
This differs to using the `attr_enccypted` approach described below for use with Rails 3 and 4, 
which requires the encrypted column name in the database to begin with `encrypted_`.

### Rails 3 and 4

Note: When using Rails 5, it is recommended to use the Active Record attribute type approach detailed above. 
However, the approach below using `attr_encrypted` is still fully supported.

Example: Model `Person` has an encrypted attribute called `name` of type string.

~~~ruby
class Person < ActiveRecord::Base
  attr_encrypted :name, random_iv: true
end
~~~

In the database migration, the `name` column should be defined as type `string` and should be large enough to hold
the base64 encoded value after encryption. If the text can be very long, use the type `text`.

~~~ruby
create_table :people, force: true do |t|
  t.string :encrypted_name
  t.string :encrypted_age
  t.text :encrypted_address
end
~~~ 

To perform a query using an encrypted field, use the encrypted form of the field name that starts with `encrypted_`:

For example: 

~~~ruby
Person.where(encrypted_name: SymmetricEncryption.encrypt("Jack")).count
~~~

By default when defining an attribute with `attr_encrypted` it will _not_ be encrypted with a 
random initialization vectore (IV). This is _not_ recommended, and `random_iv: true` should be
added whenever possible for security resaons.

However, we would never be able to perform a query using that field, since the random IV causes the 
value to change every time the same data is encrypted. As a result, the above query would never get a match.

For these columns, it is necessary to use the option `random_iv: false`:

~~~ruby
class Person < ActiveRecord::Base
  attr_encrypted :name, random_iv: false
end
~~~

Now the following query will find the expected record:

~~~ruby
Person.where(encrypted_name: SymmetricEncryption.encrypt("Jack")).count
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
* :json      => Uses JSON serialization, useful for hashes and arrays
* :yaml      => Uses YAML serialization, useful for hashes and arrays

Example: The encrypted attribute `age` can be specified as an integer:

~~~ruby
class Person < ActiveRecord::Base
  attr_encrypted :name, random_iv: false
  attr_encrypted :age, random_iv: true, type: :integer 
  attr_encrypted :address, random_iv: true, compress: true 
end
~~~

For larger encrypted attributes it is also worthwhile to compress the value after it has been encrypted,
by adding the option:
`compress: true`

#### Note

The column name in the database differs from the name of the attribute in the model. 
The encrypted column name in the database must begin with `encrypted_`.

#### Validations

To ensure that the encrypted attribute value is encrypted, a validation can be used.

Note that the validation is only applicable when using the `attr_encrypted` approach. Using the
attribute type approach with Rails 5 or above does not need a validation to ensure the field is encrypted
before saving.

~~~ruby
class Person < ActiveRecord::Base
  attr_encrypted :name, random_iv: false
  attr_encrypted :age, random_iv: true, type: :integer 
  attr_encrypted :address, random_iv: true, compress: true
   
  validates :encrypted_name, symmetric_encryption: true
  validates :encrypted_age, symmetric_encryption: true
  validates :encrypted_address, symmetric_encryption: true
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
