---
layout: default
---

## Rails Encryption

### ActiveRecord Example

```ruby
class User < ActiveRecord::Base
  # Requires table users to have a column called encrypted_bank_account_number
  attr_encrypted :bank_account_number

  # Requires users table to have a column called encrypted_social_security_number
  #
  # Note: Encrypting the same value twice will result in the _same_ encrypted value
  #       when :random_iv => false, or is not specified
  attr_encrypted :social_security_number

  # By specifying the type as :integer the value will be returned as an integer and
  # can be set as an integer, even though it is stored in the database as an
  # encrypted string
  #
  # Requires users table to have a column called encrypted_age of type string
  attr_encrypted :age,         type: integer

  # Since string and long_string are not used in the where clause of any SQL
  # queries it is better to ensure that the encrypted value is always different
  # by encrypting every value with a random Initialization Vector.
  #
  # Note: Encrypting the same value twice will result in different encrypted
  #       values when :random_iv is true
  attr_encrypted :string,      random_iv: true

  # Long encrypted strings can also be compressed prior to encryption to save
  # disk space
  attr_encrypted :long_string, random_iv: true, compress: true

  # By specifying the type as :json the value will be serialized to JSON
  # before encryption and deserialized from JSON after decryption.
  #
  # It is sometimes useful to use compression on large fields, so we can enable
  # compression before the string is encrypted
  #
  # Requires users table to have a column called encrypted_values of type string
  attr_encrypted :values,      type: :json, compress: true

  validates :encrypted_bank_account_number, symmetric_encryption: true
  validates :encrypted_social_security_number, symmetric_encryption: true
end

# Create a new user instance assigning a bank account number
user = User.new
user.bank_account_number = '12345'

# Saves the bank_account_number in the column encrypted_bank_account_number in
# encrypted form
user.save!

# Short example using create
User.create(bank_account_number: '12345')
```

Several types are supported for ActiveRecord models when encrypting or decrypting data.
Each type maps to the built-in Ruby types as follows:

- :string    => String
- :integer   => Integer
- :float     => Float
- :decimal   => BigDecimal
- :datetime  => DateTime
- :time      => Time
- :date      => Date
- :json      => Uses JSON serialization, useful for hashes and arrays
- :yaml      => Uses YAML serialization, useful for hashes and arrays

