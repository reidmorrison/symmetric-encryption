---
layout: default
---

### Symmetric Encryption for Ruby Projects using OpenSSL

Any project that wants to meet PCI compliance has to ensure that the data is encrypted
whilst in flight and at rest. Amongst many other requirements all passwords
in configuration files have to be encrypted.

This Gem helps achieve compliance by supporting encryption of data in a simple
and consistent way for Ruby and Rails projects.

Symmetric Encryption uses OpenSSL to encrypt and decrypt data, and can therefore
expose all the encryption algorithms supported by OpenSSL.

### Examples

#### Encryption Example

~~~ruby
SymmetricEncryption.encrypt "Sensitive data"
~~~

#### Decryption Example

~~~ruby
SymmetricEncryption.decrypt "JqLJOi6dNjWI9kX9lSL1XQ=="
~~~

## Features

### Encryption

* Encryption of passwords in configuration files
* Encryption of ActiveRecord model attributes by prefixing attributes / column
  names with encrypted_
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

### Backgound Job Processing

* The sister-project [Rocket Job](http://rocketjob.io) uses Symmetric Encryption
  to encrypt job data to keep it secure.
    * Rocket Job Pro can also read and write encrypted files created by Symmetric Encryption.
    * Rocket Job Pro re-uses the existing Symmetric Encryption setup for encryption and decryption.

## Encrypting Passwords in configuration files

Passwords can be encrypted in any YAML configuration file.

For example config/database.yml

~~~yaml
---
production:
  adapter:  mysql
  host:     db1w
  database: myapp_production
  username: admin
  password: <%= SymmetricEncryption.try_decrypt "JqLJOi6dNjWI9kX9lSL1XQ==\n" %>
~~~

### Notes

* Use `SymmetricEncryption.try_decrypt` to return nil if it
  fails to decrypt the value, which is essential when the encryption keys differ
  between environments
* In order for the above technique to work in non-rails YAML configuration files
  the YAML file must be processed using `ERB` prior to passing to YAML. For example

~~~ruby
    config_file = Rails.root.join('config', 'redis.yml')
    raise "redis config not found. Create a config file at: config/redis.yml" unless config_file.file?

    cfg = YAML.load(ERB.new(File.new(config_file).read).result)[Rails.env]
    raise("Environment #{Rails.env} not defined in redis.yml") unless cfg
~~~

## Large File Encryption

Example: Read and decrypt a line at a time from a file

~~~ruby
SymmetricEncryption::Reader.open('encrypted_file') do |file|
  file.each_line do |line|
     puts line
  end
end
~~~

Example: Encrypt and write data to a file

~~~ruby
SymmetricEncryption::Writer.open('encrypted_file') do |file|
  file.write "Hello World\n"
  file.write "Keep this secret"
end
~~~

Example: Compress, Encrypt and write data to a file

~~~ruby
SymmetricEncryption::Writer.open('encrypted_compressed.zip', compress: true) do |file|
  file.write "Hello World\n"
  file.write "Compress this\n"
  file.write "Keep this safe and secure\n"
end
~~~

### Ruby Platform Support

* Ruby v2.1.8, v2.2, v2.3, or higher
* JRuby v1.7.23, v9.0.5.0, or higher
* Or, Rubinius v2 or higher

### Installation

Add the following line to Gemfile

~~~ruby
gem 'symmetric-encryption'
~~~

Install the Gem with bundler

    bundle install

## Support

* Questions?
    * Join the community chat room on Gitter for [Rocket Job Support](https://gitter.im/rocketjob/support)
* [Report bugs](https://github.com/rocketjob/symmetric-encryption/issues)

## Security

Many solutions that encrypt data require the encryption keys to be stored in the
applications source code or leave it up to the developer to secure the keys on
the application servers. Symmetric Encryption takes care of securing the
symmetric encryption keys.

The following steps are used to secure the symmetric encryption keys using Symmetric Encryption:

* Symmetric Encryption keys are stored in files that are not part of the application,
its source code, or even stored in its source control system. These files can be
created, managed and further secured by System Administrators. This prevents
developers having or needing to have access to the symmetric encryption keys
* The Operating System security features limit access to the Symmetric Encryption
key files to System Administrators and the userid under which the Rails application runs.
* The files in which the Symmetric Encryption keys are stored are further
encrypted using RSA 2048 bit encryption

In order for anyone to decrypt the data being encrypted in the database, they
would need access to ALL of the following:
* A copy of the files containing the Symmetric Encryption Keys which are secured
by the Operating System
* The application source code containing the RSA private key to decrypt the above files
* The userid and password for the database to copy the encrypted data itself,
or an unsecured copy or export of the database contents

A major feature of symmetric encryption is that it makes the encryption and decryption
automatically available when the Rails application is started. This includes all
rake tasks and the Rails console. In this way data can be encrypted or decrypted as
part of any rake task.

From a security perspective it is important then to properly secure the system so that
no hacker can switch to and run as the rails user and thereby gain access to the
encryption and decryption capabilities

It is not necessary to encrypt the initialization vector (IV), and it can be placed
directly in the configuration file. The encryption key must be kept secure and
must never be placed in the configuration file or other Rails source file in production.
The IV should be generated using the rails generator described below to ensure
it is a truly random key from the entire key space. Using a human readable text
string is not considered secure.

### Limitations

By default symmetric encryption uses the same initialization vector (IV) and
encryption key to encrypt data using the SymmetricEncryption.encrypt call.
This technique is required in cases where the encrypted data is used as a key
to lookup for example a Social Security Number, since for the same input data it
must always return the same encrypted result. The drawback is that this
technique is not considered secure when encypting large amounts of data.

For non-key fields, such as storing encrypted raw responses,
use the :random_iv => true option where possible so that a
randomly generated IV is used and included in every encrypted string.

The Symmetric Encryption streaming interface SymmetricEncryption::Writer avoids this
problem by using a random IV and key in every file/stream by default.
The random IV and key are stored in the header of the output stream so that it
is available when reading back the encrypted file/stream. The key is placed
in a header on the file in encrypted form using the current global key/cipher.

The ActiveRecord `attr_encrypted` method supports the `random_iv: true` option.
Similarly for Mongoid the `random_iv: true` option can be added.

Note that encrypting the same input string with the same key and :random_iv => true
option will result in different encrypted output every time it is encrypted.

### Recommendations

* Add the encryption header to all encrypted strings.
  See the _always_add_header_ option in the configuration file.

* Add `random_iv: true` for all ActiveRecord attributes, and
  Mongoid fields which are not used in indexes and will not be used as part of a query.

### Disclaimer

Although this library has assisted in meeting PCI Compliance and has passed
previous PCI audits, it in no way guarantees that PCI Compliance will be
achieved by anyone using this library.

### Next => [Supported Frameworks](frameworks.html)
