---
layout: default
---

## Payment Card Industry (PCI) Data Security Standard (DSS)

The primary purpose of Symmetric Encryption is to secure data at rest and in-flight. It also
secures encrypted fields in flight between the application servers and the backend
databases, since the encryption/decryption occurs within the application.
Additionally, it can be used to secure files containing PII data, securing both the
network traffic generated while the file is being read/written to a network share
as well as while the files are at rest locally or on a remote network share.

Symmetric Encryption secures
* fields/attributes/data at rest.
* fields/attributes/data fields in flight since those values are encrypted within the application.
* files at rest.
* file data in flight when written across the network. 

Key:
* `data-encrypting key` is the key that is actually used to encrypt and decrypt data.
* `key-encrypting key` is used to encrypt/decrypt the `data-encrypting key` to keep it secure.

Since Symmetric Encryption is used to encrypt any sensitive data, such fields will
be refered to as PII (Personally Identifiable Information) and not just PANs as
mentioned in the PCI DSS.

PCI DSS offers 3 different ways of securing the `data-encrypting key`:
* "Encrypted with a key-encrypting key"
* "Within a secure cryptographic device (such as a hardware (host) security module (HSM) or PTS-approved point-of-interaction device)"
* "As key components or key shares, in accordance with an industry-accepted method"

#### Key-encrypting Key

By default, Symmetric Encryption uses the `key-encrypting key` approach to secure the `data-encrypting key` that
is actually used to encrypt/decrypt data.

Benefits:
* Simple.
* Great place to start.

Disadvantages:
* As the development team grows, the number of people with access to the source code and therefore the 
`key-encrypting key` increases.
* As the system administration team grows, the number of people with access to the `data-encrypting key` increases.
* Every developer needs to acknowledge in writing that they are a key custodian.

#### Secure cryptographic device

Benefits:
* `data-encrypting key` is never exposed.
* Performs encryption with dedicated hardware.

Disadvantages:
* Usually requires purchasing additional hardware.
* Cost.

#### Secure centralized Keystore / key share:

Benefits:
* `key-encrypting key` is not required.
* Reduces the number of key custodians.

Disadvantages:
* Access control cannot be secured by userid and password, since such credentials would be stored in the clear on the server.
* Using a certificate stored in the clear on the system is not sufficient since such certificate could be used 
  by an attacker to gain access to the `data-encrypting key` by connecting directly to the keystore.

## PCI Procedures

Note that Symmetric Encryption does not address the PCI DSS requirements relating to documentation.

In order to assist with PCI DSS audits, below are some of the ways that Symmetric Encryption 
assists with _v3.2_ of the [PCI DSS](https://www.pcisecuritystandards.org/security_standards/documents.php)

### Requirement 3: Protect stored cardholder data

#### 3.4 Strong Cryptography of PII wherever it is stored (PCI DSS v3.2)

3.4.a

Strong Cryptography is used to secure PII data.

The use of this strong cryptography is on a per attribute/column/field level. Not all data is encrypted, only that
which is considered PII and marked for encryption by the developer.

Testing Procedure:
* All PII fields are marked for strong cryptography in the source code as follows: 

~~~ruby
# Rails ActiveRecord example of securing `bank_account_number`
#
# A column called `encrypted_bank_account_number` should exist in the database
# that contains the encrypted bank account number. There should not be a column
# called `bank_account_number`
class User < ActiveRecord::Base
  attr_encrypted :bank_account_number
  attr_encrypted :long_string, random_iv: true, compress: true
~~~

~~~ruby
# Mongoid example of securing `bank_account_number`
#
# A column called `encrypted_bank_account_number` should exist in MongoDB
# that contains the encrypted bank account number. There should not be a column
# called `bank_account_number`
class User
  include Mongoid::Document

  field :encrypted_bank_account_number, type: String,  encrypted: true
  field :encrypted_long_string,         type: String,  encrypted: {random_iv: true, compress: true}
~~~

Notes:

* It is recommended to set `random_iv: true` for all fields that are encrypted, since
the same data will always result in different encrypted output.
    * However, it is not possible for any field that is used in lookups to use this option.
    * For example, looking for all previous instances of a specific `bank_account_number` requires
that the encrypted data always have the same output for the same input.
    * When the `random_iv` is not set for any field it should be kept short as encrypting
large amounts of data with the same `data-encrypting key` and `initialization-vector` (IV)
can eventually expose the `data-encrypting key`
    * Rotation policies to change the `data-encrypting key` can help mitigate this exposure

3.4.b, 3.4.c

* Browse the data stored in the Database, for example: MySQL, MongoDB, to confirm that
identified fields are unreadable (not plain text)
* For any files consumed or generated by the system confirm that
the required fields, or that the entire file is unreadable (not plain text)
    * This includes any files uploaded to the system, or made available for download from the system

3.4.d

* Outside the scope of Symmetric Encryption.
    * Use features built into Rails to filter logged PII fields.

#### 3.5 Procedures to protect keys (PCI DSS v3.2)

3.5.1

Review the `production` environment setting in the file `symmetric-encryption.yml`:
* `ciphers` is the list of encryption keys active in that environment.
  * The first item in the list is the key being used to encrypt data.
  * Subsequent items, each with their own version number, are used to decrypt older data.
  * `key_encrypting_key` is the `key-encrypting key`.
    * Usually a 2048 bit RSA private key.
* `key_filename` is the file name of the `data-encrypting key`.
  * This file was encrypted using the RSA public key contained in the `key-encrypting key` above. 
* `cipher_name` is the encryption algorithm and block cipher in use.
  * For example: `aes-256-cbc`, specifies AES 256 bit encryption and uses the CBC block cipher.
* `encoding` specifies how the encrypted data is encoded into a text form for storage.
  * For example:  `base64strict` specifies Base 64 encoding without the trailing newline.
  
3.5.2

Maintain separation of key custodians so that anyone with access to the `data-encrypting key` 
does _not_ also have access to the `key-encrypting key`.

* The `data-encrypting key` is limited to the user under which the application runs and
  to any production system administrator that has root / administrator access to override the read-only
  restriction
    * Verify that the `data-encrypting key` is only readable by the application user
      and not by group or everyone (Example: rails)
* The `key-encrypting key` is stored in the source code that should only be accessible to the application development team.

3.5.3a

* The `key-encrypting key` uses RSA 2048 bit encryption and therefore exceeds the strength
  of the `data-encrypting key`.
* The `data-encrypting key` is always encrypted with the `key-encrypting key`.
* The `data-encrypting key` must be placed on the system directly by a system administrator
  and must _not_ be included in the source code, or the source control repository.
* The `key-encrypting key` is stored in the source code that should only be accessible to the application development team.

3.5.3b

* Verify that the file `key_filename` above is encrypted with the `key-encrypting key`. 

3.5.3c

* The `key-encrypting key` uses RSA 2048 bit encryption and therefore exceeds the strength
  of the `data-encrypting key`.
* The `data-encrypting key` is always encrypted with the `key-encrypting key`.
* The `data-encrypting key` must be placed on the system directly by a system administrator
  and must _not_ be included in the source code, or the source control repository.
* The `key-encrypting key` is stored in the source code that should only be accessible to the application development team.

3.5.4

* The `data-encrypting key` is secured by the system administrators in key management repository with proper access controls.
* The `key-encrypting key` is only stored in the source code accessible to the application development team.
* Only servers actually running the application should contain the `data-encrypting key`.

### 3.6 Key Management Procedures (PCI DSS v3.2)

3.6.1a Key Generation

* See the `cipher_name` in `symmetric-encryption.yml` (per 3.5.1 above) and confirm that the encryption algorithm 
  and strength meet or exceed minimum requirements.

3.6.1b

* Instructions on how new keys are [generated](configuration.html) for the very first time.
* Instructions on how new keys are generated during the regular [key rotation](key_rotation.html).

3.6.2 Key Distribution

Verify the `data-encrypting key` is copied from a secure location with limited access and installed on the
required servers. 
  
Verify the `key-encrypting key` is copied from the secured source code control system during deployment.
  
3.6.3 Key Storage

Verify the `data-encrypting key` is
* only readable by the application user and not by group or everyone on the production server(s).
  * See `key_filename` in 3.5.1.
* stored by the System Administrators in a secure location with limited access.
  * Backups of the `data-encrypting key` need to be properly secured and controlled.
  
Verify the `key-encrypting key` is
* only readable by the application user and not by group or everyone on the production server(s).
  * The file `config/symmetric-encryption.yml`.
* stored in the source code in a private, secure location with limited access.
  * Backups of the source code need to be properly secured and controlled.

3.6.4, 3.6.5 Key Rotation

* Retiring or replacing active encryption keys: [key rotation](key_rotation.html).

After key rotation the retired/compromised/old `data-encrypting keys` will no longer be used for encrypting data.

The retired/compromised/old `data-encrypting keys` are retained to decrypt old or archived data.
It is however recommended to remove these old keys once all data has been re-encrypted with the new keys and old
archive data no longer needs these keys: 
* Confirm that the prior `data-encrypting keys` are no longer listed in `config/symmetric-encryption.yml`.
  * After key rotation and re-encryption of all data, there should only be one key listed under the
    `ciphers` section identified in 3.5.1.
* Confirm that the prior `data-encrypting keys` are no longer on any of the servers.

3.6.6

N/A, only applies to clear-text keys, whereas in Symmetric Encryption the `data-encrypting key` is secured 
using a `key-encrypting key`

3.6.7 Unauthorized key substitution

Procedures in place to prevent unauthorized replacement of keys:
* OS security must limit write access for `data-encryption-keys` to System Administrators only.
* A `data-encrypting key` encrypted with a different `key-encrypting key` will
  be rejected by the system on startup.

Other:

The PCI DSS also makes the following recommendation:

"In addition to the above practices, organizations may also wish to consider implementing separation of duties for 
their security functions so that security and/or audit functions are separated from operational functions. 
In environments where one individual performs multiple roles (for example, administration and security operations), 
duties may be assigned such that no single individual has end-to-end control of a process without an independent checkpoint. 
For example, responsibility for configuration and responsibility for approving changes could be assigned to separate individuals." 

Maintain separation of custodians so that anyone with access to the `data-encrypting key` 
does _not_ also have access to the `key-encrypting key`.

* The `data-encrypting key` is limited to the user under which the application runs and
  to any production system administrator that has root / administrator access to override the read-only
  restriction
    * Verify that the `data-encrypting key` is only readable by the application user
      and not by group or everyone (Example: rails)
* The `key-encrypting key` is stored in the source code that should only be accessible to the application development team.

Recommend that neither of the above key custodians have access to the database backups or media.

### Next => [API](api.html)
