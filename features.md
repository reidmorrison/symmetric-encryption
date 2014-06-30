---
layout: default
---

## Features

### Encryption

* Encryption of passwords in configuration files
* Encryption of ActiveRecord model attributes by prefixing attributes / column
  names with encrypted_
* Encryption of MongoMapper keys by using :encrypted_key
* Encryption of Mongoid model fields by adding :encrypted option to field
  definitions

### Security

* Externalization of symmetric encryption keys so that they are not in the
  source code, or the source code control system
* For maximum security supports fully random keys and initialization vectors
  extracted from the entire encryption key space
* Ability to randomly generate a new initialization vector (IV) with every
  encryption and put the IV in the encrypted data as its header

### Validators

* Validator for ActiveRecord Models to ensure fields contain encrypted data

### Files and Streams

* Stream based encryption and decryption so that large files can be read or
  written with encryption, along with a random key and IV for every file
* Stream based encryption and decryption also supports compression and decompression
  on the fly
* Randomly generate a new key and initialization vector (IV) with every
  file encryption and put the key and IV in the encrypted data as its header which
  is encrypted using the global key and IV

### Compression

* When :compress => true option is specified Symmetric Encryption will transparently
  compress the data prior to encryption.
* When decrypting compressed data Symmetric Encryption will transparently decompress
  the data after decryption based on information in the header stored in the encrypted data
* Uses built-in support in Ruby for OpenSSL and Zlib for high performance and
  maximum portability without introducing any additional dependencies

### Compatibility

* Drop in replacement for `attr_encrypted`. Just remove the `attr_encrypted` gem
