---
layout: default
---

## MongoMapper Encryption

### MongoMapper Example

To encrypt a field in a MongoMapper document, use `encrypted_key` instead of `key`
when specifying a key.

```ruby
# User model MongoMapper
class User
  include MongoMapper::Document

  key           :name,                   String
  encrypted_key :bank_account_number,    String
  encrypted_key :social_security_number, String
  encrypted_key :life_history,           String, encrypted: { random_iv: true, compress: true }

  # Encrypted fields are _always_ stored in Mongo as a String
  # To get the result back as an Integer, Symmetric Encryption will automatically
  # perform the necessary conversions
  encrypted_key :integer_value,          Integer
  encrypted_key :float_value,            Float
  encrypted_key :decimal_value,          BigDecimal
  encrypted_key :datetime_value,         DateTime
  encrypted_key :time_value,             Time
  encrypted_key :date_value,             Date
  encrypted_key :true_value,             Boolean
  encrypted_key :data_json,              Hash, encrypted: {random_iv: true, compress: true}
  # By default Hash is saved as JSON, to save as YAML add the type specifier:
  encrypted_key :data_yaml,              Hash, encrypted: {random_iv: true, compress: true, type: :yaml}

  # Optionally add validation to ensure that encrypted fields are in fact encrypted
  # before the data is saved
  validates :encrypted_bank_account_number,    symmetric_encryption: true
  validates :encrypted_social_security_number, symmetric_encryption: true
end

# Create a new user document
User.create(bank_account_number: '12345')

# When finding a document, always use the encrypted form of the field name
user = User.where(encrypted_bank_account_number: SymmetricEncryption.encrypt('12345')).first

# Fields can be accessed using their unencrypted names
puts user.bank_account_number
```
