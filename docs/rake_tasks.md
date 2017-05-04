---
layout: default
---

## Rake Tasks

For PCI compliance developers should not be the ones creating or encrypting
passwords. The following rake tasks can be used by system administrators to
generate and encrypt passwords for databases, or external web calls.
It is safe to pass the encrypted password for say MySQL to the developers
who can then put it in the config files which are kept in source control.

#### Generating random passwords

Generate a random password and display its encrypted form:

    rake symmetric_encryption:random_password

#### Encrypting passwords and other strings

Encrypt a known value, such as a password:

    rake symmetric_encryption:encrypt

Note: Passwords must be encrypted in the environment in which they will be used.
  Since each environment should have its own symmetric encryption keys

Note: To use the rake task 'symmetric_encryption:encrypt' the gem 'highline'
  must first be installed by adding to bundler or installing directly:

~~~ruby
gem install 'highline'
~~~

#### Encrypting Files

Encrypt a file from the command line using a Rake Task

    INFILE="Gemfile.lock" OUTFILE="Gemfile.lock.encrypted" rake symmetric_encryption:encrypt_file

Encrypt and compress a file at the same time

    INFILE="Gemfile.lock" OUTFILE="Gemfile.lock.encrypted" COMPRESS=1 rake symmetric_encryption:encrypt_file

#### Decrypting Files

Decrypt a file previously encrypted with symmetric encryption

    INFILE="Gemfile.lock.encrypted" OUTFILE="Gemfile.lock2" rake symmetric_encryption:decrypt_file

When decrypting a compressed file it is not necessary to specify whether the file was compressed
since the header embedded in the file will indicate whether it was compressed

The file header also contains a random key and iv used to encrypt the files contents.
The key and iv is encrypted with the global encryption key being used by the symmetric
encryption installation.

### Next => [Key Rotation](key_rotation.html)
