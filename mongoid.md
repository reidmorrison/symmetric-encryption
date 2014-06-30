---
layout: default
---

## Mongoid Example

To encrypt a field in a Mongoid document, just add "encrypted: true" at the end
of the field specifier. The field name must currently begin with "encrypted_"

```ruby
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
```

### Validation Example

```ruby
class MyModel < ActiveRecord::Base
  validates :encrypted_ssn, symmetric_encryption: true
end

m = MyModel.new
m.valid?
#  => false
m.encrypted_ssn = SymmetricEncryption.encrypt('123456789')
m.valid?
#  => true
```
