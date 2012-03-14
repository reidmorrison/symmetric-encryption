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
    # Just use test symmetric encryption keys in the development environment
    # No private key required since we are not reading the keys from a file
    development: &development_defaults
      cipher: aes-256-cbc
      symmetric_key: 1234567890ABCDEF1234567890ABCDEF
      symmetric_iv: 1234567890ABCDEF

    test:
      <<: *development_defaults

    release: &release_defaults
      # Since the key to encrypt and decrypt with must NOT be stored along with the
      # source code, we only hold a RSA key that is used to unlock the file
      # containing the actual symmetric encryption key
      #
      # To generate a new RSA private key:
      #    openssl genrsa 2048
      private_rsa_key: |
        -----BEGIN RSA PRIVATE KEY-----
           ...
           paste RSA key generated above here
           ...
        -----END RSA PRIVATE KEY-----

      # Filename containing Symmetric Encryption Key
      # Note: The file contents must be RSA 2048 bit encrypted
      #       with the public key derived from the private key above
      symmetric_key_filename: /etc/rails/.rails.key
      symmetric_iv_filename: /etc/rails/.rails.iv

      # Use aes-256-cbc encryption
      cipher: aes-256-cbc

    hotfix:
      <<: *release_defaults

    production:
      <<: *release_defaults

This configuration file should be checked into the source code control system.
It does Not include the Symmetric Encryption keys. They will be generated in the
next step.

### Generating and securing the Symmetric Encryption keys

The symmetric encryption key consists of the key itself and an optional
initialization vector.

To generate the keys run the following Rake task in each environment:

    RAILS_ENV=release rake symmetric_encryption:generate_symmetric_keys

Replace 'release' as necessary for each environment.

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

For complete PCI compliance it is necessary to change the Symmetric Encryption
keys every year. During the transition period of moving from one encryption
key to another symmetric-encryption supports multiple Symmetric Encryption keys.
If decryption with the current key fails, any previous keys will also be tried
automatically.

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
    # Just use test symmetric encryption keys in the development environment
    # No private key required since we are not reading the keys from a file
    development: &development_defaults
      cipher: aes-256-cbc
      symmetric_key: 1234567890ABCDEF1234567890ABCDEF
      symmetric_iv: 1234567890ABCDEF

    test:
      <<: *development_defaults

    release: &release_defaults
      # Since the key to encrypt and decrypt with must NOT be stored along with the
      # source code, we only hold a RSA key that is used to unlock the file
      # containing the actual symmetric encryption key
      #
      # To generate a new RSA private key:
      #    openssl genrsa 2048
      private_rsa_key: |
        -----BEGIN RSA PRIVATE KEY-----
           ...
           paste RSA key generated above here
           ...
        -----END RSA PRIVATE KEY-----

      # Filename containing Symmetric Encryption Key
      # Note: The file contents must be RSA 2048 bit encrypted
      #       with the public key derived from the private key above
      symmetric_key_filename: /etc/rails/.rails.key
      symmetric_iv_filename: /etc/rails/.rails.iv

      # Use aes-256-cbc encryption
      cipher: aes-256-cbc

    hotfix:
      <<: *release_defaults

    production:
      <<: *release_defaults



Meta
----

* Code: `git clone git://github.com/ClarityServices/symmetric-encryption.git`
* Home: <https://github.com/ClarityServices/symmetric-encryption>
* Bugs: <http://github.com/ClarityServices/symmetric-encryption/issues>
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
