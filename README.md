symmetric-encryption
====================

* http://github.com/ClarityServices/symmetric-encryption

## Introduction

Any project that wants to meet PCI compliance has to ensure that the data is encrypted
whilst in flight and at rest. Amongst many other other requirements all passwords
in configuration files have to be encrypted

This Gem helps achieve compliance by supporting encryption of data in a simple
and consistent way

## Security

Many solutions that encrypt data require the encryption keys to be stored in the
applications source code or leave it up to the developer to secure the keys on
the application servers. symmetric-encryption takes care of securing the
symmetric encryption keys.

The following steps are used to secure the symmetric encryption keys using symmetric-encryption:

* Symmetric Encryption keys are stored in files that are not part of the application,
its source code, or even stored in its source control system. These files can be
created, managed and further secured by System Administrators. This prevents
developers having or needing to have access to the symmetric encryption keys
* The Operating System security features limit access to the Symmetric Encryption
key files to System Administrators and the userid under which the Rails application runs.
* The files in which the Symmetric Encryption keys are stored are futher
encrypted using RSA 2048 bit encryption

In order for anyone to decrypt the data being encrypted in the database, they
would need access to ALL of the following:
* A copy of the files containing the Symmetric Encryption Keys which are secured
by the Operating System
* The application source code containing the RSA private key to decrypt the above files
* The userid and password for the database to copy the encrypted data itself,
or an unsecured copy or export of the database contents

## Features

* Encryption of passwords in configuration files
* Encryption of ActiveRecord model attributes by prefixing attributes / column
names with encrypted_
* Externalization of symmetric encryption keys so that they are not in the
  source code, or the source code control system
* Drop in replacement for attr_encrypted. Just remove the attr_encrypted gem
* Compatible with the default Encryption algorithm in attr_encrypted
* More efficient replacement for attr_encrypted since only ActiveRecord Models
are extended with encrypted_ behavior, rather than every object in the system
* Custom validator for ActiveRecord Models

## Examples

### Encryption Example

    Symmetric::Encryption.encrypt "Sensitive data"

### Decryption Example

    Symmetric::Encryption.decrypt "JqLJOi6dNjWI9kX9lSL1XQ==\n"

### Validation Example

    class MyModel < ActiveRecord::Base
      validates :encrypted_ssn, :symmetric_encrypted => true
    end

    m = MyModel.new
    m.valid?
    #  => false
    m.encrypted_ssn = Symmetric::Encryption.encrypt('123456789')
    m.valid?
    #  => true

### Encrypting Passwords in configuration files

Passwords can be encrypted in any YAML configuration file.

For example config/database.yml

    production:
      adapter:  mysql
      host:     db1w
      database: myapp_production
      username: admin
      password: <%= Symmetric::Encryption.try_decrypt "JqLJOi6dNjWI9kX9lSL1XQ==\n" %>

Note: Use Symmetric::Encryption.try_decrypt method which will return nil if it
  fails to decrypt the value, which is essential when the encryption keys differ
  between environments

Note: In order for the above technique to work in other YAML configuration files
  the YAML file must be processed using ERB prior to passing to YAML. For example

    config_file = Rails.root.join('config', 'redis.yml')
    raise "redis config not found. Create a config file at: config/redis.yml" unless config_file.file?

    cfg = YAML.load(ERB.new(File.new(config_file).read).result)[Rails.env]
    raise("Environment #{Rails.env} not defined in redis.yml") unless cfg

### Generating encrypted passwords

The following rake task can be used to generate encrypted passwords for the
specified environment

Note: Passwords must be encrypted in the environment in which they will be used.
  Since each environment should have its own symmetric encryption keys

## Install

  gem install symmetric-encryption

## Configuration

### Generating the RSA Private key

To protect the files holding the Symmetric Encryption keys, symmetric-encryption uses 2048 bit RSA
encryption.

Generate the RSA Private key as follows

    openssl genrsa 2048

Paste the output into the configuration created below

### Creating the configuration file

Create a configuration file in config/symmetric-encryption.yml per the following example:

    #
    # Symmetric Encryption for Ruby
    #
    ---
    # For the development and test environments the test symmetric encryption keys
    # can be placed directly in the source code.
    # And therefore no RSA private key is required
    development: &development_defaults
      key: 1234567890ABCDEF1234567890ABCDEF
      iv: 1234567890ABCDEF
      cipher: aes-128-cbc

    test:
      <<: *development_defaults

    production:
      # Since the key to encrypt and decrypt with must NOT be stored along with the
      # source code, we only hold a RSA key that is used to unlock the file
      # containing the actual symmetric encryption key
      #
      # Sample RSA Key, DO NOT use this RSA key, generate a new one using
      #    openssl genrsa 2048
      private_rsa_key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEAxIL9H/jYUGpA38v6PowRSRJEo3aNVXULNM/QNRpx2DTf++KH
        6DcuFTFcNSSSxG9n4y7tKi755be8N0uwCCuOzvXqfWmXYjbLwK3Ib2vm0btpHyvA
        qxgqeJOOCxKdW/cUFLWn0tACUcEjVCNfWEGaFyvkOUuR7Ub9KfhbW9cZO3BxZMUf
        IPGlHl/gWyf484sXygd+S7cpDTRRzo9RjG74DwfE0MFGf9a1fTkxnSgeOJ6asTOy
        fp9tEToUlbglKaYGpOGHYQ9TV5ZsyJ9jRUyb4SP5wK2eK6dHTxTcHvT03kD90Hv4
        WeKIXv3WOjkwNEyMdpnJJfSDb5oquQvCNi7ZSQIDAQABAoIBAQCbzR7TUoBugU+e
        ICLvpC2wOYOh9kRoFLwlyv3QnH7WZFWRZzFJszYeJ1xr5etXQtyjCnmOkGAg+WOI
        k8GlOKOpAuA/PpB/leJFiYL4lBwU/PmDdTT0cdx6bMKZlNCeMW8CXGQKiFDOcMqJ
        0uGtH5YD+RChPIEeFsJxnC8SyZ9/t2ra7XnMGiCZvRXIUDSEIIsRx/mOymJ7bL+h
        Lbp46IfXf6ZuIzwzoIk0JReV/r+wdmkAVDkrrMkCmVS4/X1wN/Tiik9/yvbsh/CL
        ztC55eSIEjATkWxnXfPASZN6oUfQPEveGH3HzNjdncjH/Ho8FaNMIAfFpBhhLPi9
        nG5sbH+BAoGBAOdoUyVoAA/QUa3/FkQaa7Ajjehe5MR5k6VtaGtcxrLiBjrNR7x+
        nqlZlGvWDMiCz49dgj+G1Qk1bbYrZLRX/Hjeqy5dZOGLMfgf9eKUmS1rDwAzBMcj
        M9jnnJEBx8HIlNzaR6wzp3GMd0rrccs660A8URvzkgo9qNbvMLq9vyUtAoGBANll
        SY1Iv9uaIz8klTXU9YzYtsfUmgXzw7K8StPdbEbo8F1J3JPJB4D7QHF0ObIaSWuf
        suZqLsvWlYGuJeyX2ntlBN82ORfvUdOrdrbDlmPyj4PfFVl0AK3U3Ai374DNrjKR
        hF6YFm4TLDaJhUjeV5C43kbE1N2FAMS9LYtPJ44NAoGAFDGHZ/E+aCLerddfwwun
        MBS6MnftcLPHTZ1RimTrNfsBXipBw1ItWEvn5s0kCm9X24PmdNK4TnhqHYaF4DL5
        ZjbQK1idEA2Mi8GGPIKJJ2x7P6I0HYiV4qy7fe/w1ZlCXE90B7PuPbtrQY9wO7Ll
        ipJ45X6I1PnyfOcckn8yafUCgYACtPAlgjJhWZn2v03cTbqA9nHQKyV/zXkyUIXd
        /XPLrjrP7ouAi5A8WuSChR/yx8ECRgrEM65Be3qBEtoGCB4AS1G0NcigM6qhKBFi
        VS0aMXr3+V8argcUIwJaWW/x+p2go48yXlJpLHPweeXe8mXEt4iM+QZte6p2yKQ4
        h9PGQQKBgQCqSydmXBnXGIVTp2sH/2GnpxLYnDBpcJE0tM8bJ42HEQQgRThIChsn
        PnGA91G9MVikYapgI0VYBHQOTsz8rTIUzsKwXG+TIaK+W84nxH5y6jUkjqwxZmAz
        r1URaMAun2PfAB4g2N/kEZTExgeOGqXjFhvvjdzl97ux2cTyZhaTXg==
        -----END RSA PRIVATE KEY-----

      # List Symmetric Key files in the order of current / latest first
      ciphers:
        -
          # Filename containing Symmetric Encryption Key encrypted using the
          # RSA public key derived from the private key above
          key_filename: /etc/rails/.rails.key
          iv_filename: /etc/rails/.rails.iv

          # Encryption cipher
          #   Recommended values:
          #      aes-256-cbc
          #         256 AES CBC Algorithm. Very strong
          #         Ruby 1.8.7 MRI Approximately 100,000 encryptions or decryptions per second
          #         JRuby 1.6.7 with Ruby 1.8.7 Approximately 22,000 encryptions or decryptions per second
          #      aes-128-cbc
          #         128 AES CBC Algorithm. Less strong.
          #         Ruby 1.8.7 MRI Approximately 100,000 encryptions or decryptions per second
          #         JRuby 1.6.7 with Ruby 1.8.7 Approximately 22,000 encryptions or decryptions per second
          cipher: aes-256-cbc

This configuration file should be checked into the source code control system.
It does Not include the Symmetric Encryption keys. They will be generated in the
next step.

### Generating and securing the Symmetric Encryption keys

The symmetric encryption key consists of the key itself and an optional
initialization vector.

To generate the keys run the following Rake task in each environment:

    RAILS_ENV=production rake symmetric_encryption:generate_symmetric_keys

Replace 'production' as necessary for each environment.

Make sure that the current user has read and write access to the folder listed
in the configuration option symmetric_key_filename above.

Once the Symmetric Encryption keys have been generated, secure them further by
making the files read-only to the Rails user and not readable by any other user

    chmod ...

When running multiple Rails servers in a particular environment copy the same
key files to every server in that environment. I.e. All Rails servers in each
environment must run the same encryption keys.

Note: The generate step above must only be run once in each environment

## Using in non-Rails environments

symmetric-encryption can also be used in non-Rails environment. At application
startup, run the code below to initialize symmetric-encryption prior to
attempting to encrypt or decrypt any data

    require 'symmetric-encryption'
    Symmetric::Encryption.load!('config/symmetric-encryption.yml', 'production')

Parameters:

* Filename of the configuration file created above
* Name of the environment to load the configuration for

To manually generate the symmetric encryption keys, run the code below

    require 'symmetric-encryption'
    Symmetric::Encryption.generate_symmetric_key_files('config/symmetric-encryption.yml', 'production')

Parameters:

* Filename of the configuration file created above
* Name of the environment to load the configuration for

## Supporting Multiple Encryption Keys

According to the PCI Compliance documentation: "Cryptographic keys must be changed on an annual basis."

During the transition period of moving from one encryption key to another
symmetric-encryption supports multiple Symmetric Encryption keys. If decryption
with the current key fails, any previous keys will also be tried automatically.

By default the latest key is used for encrypting data. Another key can be specified
for encryption so that old data can be looked in queries, etc.

Since just the Symmetric Encryption keys are being changed, we can still continue to
use the same RSA Private key for gaining access to the Symmetric Encryption Keys

### Configuring multiple Symmetric Encryption keys

Create a configuration file in config/symmetric-encryption.yml per the following example:

    #
    # Symmetric Encryption for Ruby
    #
    ---
    # For the development and test environments the test symmetric encryption keys
    # can be placed directly in the source code.
    # And therefore no RSA private key is required
    development: &development_defaults
      key: 1234567890ABCDEF1234567890ABCDEF
      iv: 1234567890ABCDEF
      cipher: aes-128-cbc

    test:
      <<: *development_defaults

    production:
      # Since the key to encrypt and decrypt with must NOT be stored along with the
      # source code, we only hold a RSA key that is used to unlock the file
      # containing the actual symmetric encryption key
      #
      # Sample RSA Key, DO NOT use this RSA key, generate a new one using
      #    openssl genrsa 2048
      private_rsa_key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEAxIL9H/jYUGpA38v6PowRSRJEo3aNVXULNM/QNRpx2DTf++KH
        6DcuFTFcNSSSxG9n4y7tKi755be8N0uwCCuOzvXqfWmXYjbLwK3Ib2vm0btpHyvA
        qxgqeJOOCxKdW/cUFLWn0tACUcEjVCNfWEGaFyvkOUuR7Ub9KfhbW9cZO3BxZMUf
        IPGlHl/gWyf484sXygd+S7cpDTRRzo9RjG74DwfE0MFGf9a1fTkxnSgeOJ6asTOy
        fp9tEToUlbglKaYGpOGHYQ9TV5ZsyJ9jRUyb4SP5wK2eK6dHTxTcHvT03kD90Hv4
        WeKIXv3WOjkwNEyMdpnJJfSDb5oquQvCNi7ZSQIDAQABAoIBAQCbzR7TUoBugU+e
        ICLvpC2wOYOh9kRoFLwlyv3QnH7WZFWRZzFJszYeJ1xr5etXQtyjCnmOkGAg+WOI
        k8GlOKOpAuA/PpB/leJFiYL4lBwU/PmDdTT0cdx6bMKZlNCeMW8CXGQKiFDOcMqJ
        0uGtH5YD+RChPIEeFsJxnC8SyZ9/t2ra7XnMGiCZvRXIUDSEIIsRx/mOymJ7bL+h
        Lbp46IfXf6ZuIzwzoIk0JReV/r+wdmkAVDkrrMkCmVS4/X1wN/Tiik9/yvbsh/CL
        ztC55eSIEjATkWxnXfPASZN6oUfQPEveGH3HzNjdncjH/Ho8FaNMIAfFpBhhLPi9
        nG5sbH+BAoGBAOdoUyVoAA/QUa3/FkQaa7Ajjehe5MR5k6VtaGtcxrLiBjrNR7x+
        nqlZlGvWDMiCz49dgj+G1Qk1bbYrZLRX/Hjeqy5dZOGLMfgf9eKUmS1rDwAzBMcj
        M9jnnJEBx8HIlNzaR6wzp3GMd0rrccs660A8URvzkgo9qNbvMLq9vyUtAoGBANll
        SY1Iv9uaIz8klTXU9YzYtsfUmgXzw7K8StPdbEbo8F1J3JPJB4D7QHF0ObIaSWuf
        suZqLsvWlYGuJeyX2ntlBN82ORfvUdOrdrbDlmPyj4PfFVl0AK3U3Ai374DNrjKR
        hF6YFm4TLDaJhUjeV5C43kbE1N2FAMS9LYtPJ44NAoGAFDGHZ/E+aCLerddfwwun
        MBS6MnftcLPHTZ1RimTrNfsBXipBw1ItWEvn5s0kCm9X24PmdNK4TnhqHYaF4DL5
        ZjbQK1idEA2Mi8GGPIKJJ2x7P6I0HYiV4qy7fe/w1ZlCXE90B7PuPbtrQY9wO7Ll
        ipJ45X6I1PnyfOcckn8yafUCgYACtPAlgjJhWZn2v03cTbqA9nHQKyV/zXkyUIXd
        /XPLrjrP7ouAi5A8WuSChR/yx8ECRgrEM65Be3qBEtoGCB4AS1G0NcigM6qhKBFi
        VS0aMXr3+V8argcUIwJaWW/x+p2go48yXlJpLHPweeXe8mXEt4iM+QZte6p2yKQ4
        h9PGQQKBgQCqSydmXBnXGIVTp2sH/2GnpxLYnDBpcJE0tM8bJ42HEQQgRThIChsn
        PnGA91G9MVikYapgI0VYBHQOTsz8rTIUzsKwXG+TIaK+W84nxH5y6jUkjqwxZmAz
        r1URaMAun2PfAB4g2N/kEZTExgeOGqXjFhvvjdzl97ux2cTyZhaTXg==
        -----END RSA PRIVATE KEY-----

      # List Symmetric Key files in the order of current / latest first
      ciphers:
        -
          # Filename containing Symmetric Encryption Key encrypted using the
          # RSA public key derived from the private key above
          key_filename: /etc/rails/.rails.key
          iv_filename: /etc/rails/.rails.iv

          # Encryption cipher
          #   Recommended values:
          #      aes-256-cbc
          #         256 AES CBC Algorithm. Very strong
          #         Ruby 1.8.7 MRI Approximately 100,000 encryptions or decryptions per second
          #         JRuby 1.6.7 with Ruby 1.8.7 Approximately 22,000 encryptions or decryptions per second
          #      aes-128-cbc
          #         128 AES CBC Algorithm. Less strong.
          #         Ruby 1.8.7 MRI Approximately 100,000 encryptions or decryptions per second
          #         JRuby 1.6.7 with Ruby 1.8.7 Approximately 22,000 encryptions or decryptions per second
          cipher: aes-256-cbc

        -
          # OPTIONAL:
          #
          # Any previous Symmetric Encryption Keys
          #
          # Only used when old data still exists that requires old decryption keys
          # to be used
          key_filename: /etc/rails/.rails_old.key
          iv_filename: /etc/rails/.rails_old.iv
          cipher:   aes-256-cbc

## Possible Future Enhancements

Submit an issue ticket to request any of the following features:

* Ability to entirely disable encryption for a specific environment.
  Symmetric::Encryption.encrypt() would return the supplied data without encrypting it and
  Symmetric::Encryption.decrypt() would return the supplied data without decrypting it

* Support for automatically compressing data prior to encrypting it when the
  data exceeds some predefined size. And automatically decompressing the data
  during decryption

* Make attr_encrypted auto-detect the encrypted column type and Base64 encode
  when type is CHAR and store as binary when type is BINARY or BLOB

* Create rake task / generator to generate a sample configuration file
  with a new RSA Private key already in it

* Ability to change Symmetric::Encryption configuration options from custom
  Rails initializers, rather than having everything in the config file.
  For example config.symmetric_encryption.cipher = 'aes-128-cbc'

Meta
----

* Code: `git clone git://github.com/ClarityServices/symmetric-encryption.git`
* Home: <https://github.com/ClarityServices/symmetric-encryption>
* Issues: <http://github.com/ClarityServices/symmetric-encryption/issues>
* Gems: <http://rubygems.org/gems/symmetric-encryption>

This project uses [Semantic Versioning](http://semver.org/).

Authors
-------

Reid Morrison :: reidmo@gmail.com :: @reidmorrison

License
-------

Copyright 2012 Clarity Services, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Compliance
----------

Although this library has assisted Clarity in meeting PCI Compliance it in no
way guarantees that PCI Compliance will be met by anyone using this library
for encryption purposes.
