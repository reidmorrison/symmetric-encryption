# Symmetric Encryption
[![Gem Version](https://img.shields.io/gem/v/symmetric-encryption.svg)](https://rubygems.org/gems/symmetric-encryption) [![Build Status](https://github.com/reidmorrison/symmetric-encryption/workflows/build/badge.svg)](https://github.com/reidmorrison/symmetric-encryption/actions?query=workflow%3Abuild) [![Downloads](https://img.shields.io/gem/dt/symmetric-encryption.svg)](https://rubygems.org/gems/symmetric-encryption) [![License](https://img.shields.io/badge/license-Apache%202.0-brightgreen.svg)](http://opensource.org/licenses/Apache-2.0) ![](https://img.shields.io/badge/status-Production%20Ready-blue.svg) 

* https://encryption.rocketjob.io/

Transparently encrypt ActiveRecord, and Mongoid attributes. Encrypt passwords in configuration files. Encrypt entire files at rest.

## Introduction

Any project that wants to meet PCI compliance has to ensure that the data is encrypted
whilst in flight and at rest. Amongst many other requirements all passwords
in configuration files also have to be encrypted.

Symmetric Encryption helps achieve compliance by supporting encryption of data in a simple
and consistent way.

Symmetric Encryption uses OpenSSL to encrypt and decrypt data, and can therefore
expose all the encryption algorithms supported by OpenSSL.

## Documentation

[Symmetric Encryption Guide](https://encryption.rocketjob.io/)

## Rocket Job

Checkout the sister project [Rocket Job](http://rocketjob.io): Ruby's missing batch system.

Fully supports Symmetric Encryption to encrypt data in flight and at rest while running jobs in the background.

## Upgrading to SymmetricEncryption V4

Version 4 of Symmetric Encryption has completely adopted the Ruby keyword arguments on most API's where
multiple arguments are being passed, or where a Hash was being used before.

The encrypt and decrypt API now require keyword arguments for any optional arguments.

The following does _not_ change:

~~~ruby
encrypted = SymmetricEncryption.encrypt('Hello World')
SymmetricEncryption.decrypt(encrypted)
~~~

The following is _not_ backward compatible:
~~~ruby
SymmetricEncryption.encrypt('Hello World', false, false, :date)
~~~

Needs to be changed to:
~~~ruby
SymmetricEncryption.encrypt('Hello World', random_iv: false, compress: false, type: :date)
~~~

Or, just to change the type:
~~~ruby
SymmetricEncryption.encrypt('Hello World', type: :date)
~~~

Similarly the `decrypt` api has also changed:
~~~ruby
SymmetricEncryption.decrypt(encrypted, 2, :date)
~~~

Needs to be changed to:
~~~ruby
SymmetricEncryption.decrypt(encrypted, version: 2, type: :string)
~~~

The Rake tasks have been replaced with a new command line interface for managing key configuration and generation. 
For more info:
~~~
symmetric-encryption --help
~~~

#### Configuration changes

In Symmetric Encryption V4 the configuration file is now modified directly instead
of using templates. This change is necessary to allow the command line interface to
generate new keys and automatically update the configuration file.
 
Please backup your existing `symmetric-encryption.yml` prior to upgrading if it is not
already in a version control system. This is critical for configurations that have custom
code or for prior configurations targeting heroku.

In Symmetric Encryption V4 the defaults for `encoding` and `always_add_header` have changed.
If these values are not explicitly set in the `symmetric-encryption.yml` file, set them
prior to upgrading.

Prior defaults, set explicitly to these values if missing for all environments:
~~~yaml
      encoding:          :base64
      always_add_header: false
~~~

New defaults are:
~~~yaml
      encoding:          :base64strict
      always_add_header: true
~~~


## Upgrading to SymmetricEncryption V3

In version 3 of SymmetricEncryption, the following changes have been made that
may have backward compatibility issues:

* `SymmetricEncryption.decrypt` no longer rotates through all the decryption keys
  when previous ciphers fail to decrypt the encrypted string.
  In a very small, yet significant number of cases it was possible to decrypt data
  using the incorrect key. Clearly the data returned was garbage, but it still
  returned a string of data instead of throwing an exception.
  See `SymmetricEncryption.select_cipher` to supply your own custom logic to
  determine the correct cipher to use when the encrypted string does not have a
  header and multiple ciphers are defined.

* Configuration file format prior to V1 is no longer supported.

* New configuration option has been added to support setting encryption keys
  from environment variables.

* `Cipher.parse_magic_header!` now returns a Struct instead of an Array.

* New config options `:encrypted_key` and `:encrypted_iv` to support setting
  the encryption key in environment variables, or from other sources such as ldap
  or a central directory service.

## New features in V1.1 and V2

* Ability to randomly generate a new initialization vector (iv) with every
  encryption and put the iv in the encrypted data as its header, without having
  to use `SymmetricEncryption::Writer`.

* With file encryption randomly generate a new key and initialization vector (iv) with every
  file encryption and put the key and iv in the encrypted data as its header which
  is encrypted using the global key and iv.

* Support for compression.

* `SymmetricEncryption.encrypt` has two additional optional parameters:
    * random_iv `[true|false]`
        * Whether the encypted value should use a random IV every time the
          field is encrypted.
        * It is recommended to set this to true where feasible. If the encrypted
          value could be used as part of a SQL where clause, or as part
          of any lookup, then it must be false.
        * Setting random_iv to true will result in a different encrypted output for
          the same input string.
        * Note: Only set to true if the field will never be used as part of
          the where clause in an SQL query.
        * Note: When random_iv is true it will add a 8 byte header, plus the bytes
          to store the random IV in every returned encrypted string, prior to the
          encoding if any.
        * Note: Adds a 6 byte header prior to encoding, if not already configured
          to add the header to all encrypted values.
        * Default: false
        * Highly Recommended where feasible: true

    * compress [true|false]
        * Whether to compress prior to encryption.
        * Should only be used for large strings since compression overhead and
          the overhead of adding the 'magic' header may exceed any benefits of
          compression.
        * Default: false

## Author

[Reid Morrison](https://github.com/reidmorrison)

[Contributors](https://github.com/reidmorrison/symmetric-encryption/graphs/contributors)

## Versioning

This project uses [Semantic Versioning](http://semver.org/).

## Disclaimer

Although this library has assisted in meeting PCI Compliance and has passed
previous PCI audits, it in no way guarantees that PCI Compliance will be
achieved by anyone using this library.
