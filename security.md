---
layout: default
---

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

## Limitations

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
Similarly for MongoMapper and Mongoid the `random_iv: true` option can be added.

Note that encrypting the same input string with the same key and :random_iv => true
option will result in different encrypted output every time it is encrypted.

## Recommendations

* Add the encryption header to all encrypted strings.
  See the _always_add_header_ option in the configuration file.

* Add `random_iv: true` for all ActiveRecord attributes, MongoMapper keys, and
  Mongoid fields which are not used in indexes and will not be used as part of a query.

