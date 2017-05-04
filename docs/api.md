---
layout: default
---

## SymmetricEncryption API

### Quick Test

Before configuration or generating keys SymmetricEncryption can be used in a
standalone test scenario:

~~~ruby
# Use test encryption keys
SymmetricEncryption.cipher = SymmetricEncryption::Cipher.new(
  key:         '1234567890ABCDEF',
  iv:          '1234567890ABCDEF',
  cipher_name: 'aes-128-cbc'
)

encrypted = SymmetricEncryption.encrypt('hello world')

puts SymmetricEncryption.decrypt(encrypted)
~~~

### SymmetricEncryption.encrypt

Encrypt the supplied string using Symmetric Encryption

~~~ruby
SymmetricEncryption.encrypt(str, random_iv=false, compress=false, type=:string)
~~~

- Returns a Base64 encoded string
- Returns nil if the supplied `str` is nil
- Returns "" if it is a string and it is empty

Parameters

#### `value` [Object]

String to be encrypted. If `str` is not a string, #to_s will be called on it
to convert it to a string

#### `random_iv` [true|false]

Whether the encrypted value should use a random IV every time the field is encrypted.
It is recommended to set this to true where feasible. If the encrypted
value could be used as part of a SQL where clause, or as part
of any lookup, then it must be false.

Setting random_iv to true will result in a different encrypted output for
the same input string.

Note: Only set to true if the field will never be used as part of
  the where clause in an SQL query.

Note: When random_iv is true it will add a 8 byte header, plus the bytes
  to store the random IV in every returned encrypted string, prior to the
  encoding if any.

Default: false
Highly Recommended where feasible: true

#### `compress` [true|false]

Whether to compress `str` before encryption.

Should only be used for large strings since compression overhead and
the overhead of adding the 'magic' header may exceed any benefits of
compression.

Note: Adds a 6 byte header prior to encoding, only if :random_iv is false
Default: false

#### `type` [:string|:integer|:float|:decimal|:datetime|:time|:date|:boolean]

Expected data type of the value to encrypt.

Uses the coercible gem to coerce non-string values into string values.

When type is set to :string (the default), uses #to_s to convert
non-string values to string values.

Note: If type is set to something other than :string, it's expected that
  the coercible gem is available in the path.

Default: :string

### SymmetricEncryption.decrypt

Decrypt string previously encrypted with Symmetric Encryption

~~~ruby
SymmetricEncryption.decrypt(encrypted_and_encoded_string, version=nil, type=:string)
~~~

- Returns decrypted value
   - On decryption an attempt is made to encode the data as UTF-8, if it fails it
     will be returned as BINARY encoded.
- Returns nil if the supplied value is nil
- Returns "" if it is a string and it is empty
- Raises OpenSSL::Cipher::CipherError when `str` was not encrypted using
the primary key and iv

Parameters:

#### `str` [String]

Encrypted string to decrypt

#### `version` [Integer]

Specify which cipher version to use if no header is present on the encrypted string

#### `type` [:string|:integer|:float|:decimal|:datetime|:time|:date|:boolean]

- If value is set to something other than `:string`, then the coercible gem
  will be use to coerce the unencrypted string value into the specified
  type. This assumes that the value was stored using the same type.
- Note: If type is set to something other than `:string`, it's expected
  that the coercible gem is available in the path.
- Default: :string

If the supplied string has an encryption header then the cipher matching
the version number in the header will be used to decrypt the string

When no header is present in the encrypted data, a custom Block/Proc can
be supplied to determine which cipher to use to decrypt the data.
see #cipher_selector=

