---
layout: default
---

## Configuring a standalone Symmetric Encryption installation

SymmetricEncryption can also be used standalone and in non-Rails environments.

Install SymmetricEncryption

    gem install symmetric-encryption

### Give it a try

To tryout Symmetric Encryption standalone and without generating any configuration files or
keys yet:

Open an `irb` console and run the following code:

~~~ruby
require 'symmetric-encryption'
# Test cipher
SymmetricEncryption.cipher = SymmetricEncryption::Cipher.new(
  cipher_name: 'aes-128-cbc',
  key:         '1234567890ABCDEF',
  iv:          '1234567890ABCDEF',
  encoding:    :base64strict
)

encrypted = SymmetricEncryption.encrypt 'Hello World'

# => "NIuPIXv/ii1IP1dF6T0NpQ=="

SymmetricEncryption.decrypt(encrypted)

# => "Hello World"
~~~

### Create configuration file

Manually create a symmetric-encryption.yml configuration file based on the
one supplied in [examples/symmetric-encryption.yml](https://github.com/reidmorrison/symmetric-encryption/blob/master/examples/symmetric-encryption.yml).

TODO: Add a command to generate a new stand-alone config file

### Development use

The configuration file above can be used immediately for development and testing purposes as follows:

~~~ruby
require 'symmetric-encryption'
SymmetricEncryption.load!('symmetric-encryption.yml', 'development')

encrypted = SymmetricEncryption.encrypt 'Hello World'

SymmetricEncryption.decrypt(encrypted)
~~~

Parameters:

* Filename of the configuration file created above
* Name of the environment to load the configuration for

#### Save to version control

The configuration file should be checked into the source code control system.
It does Not include the Symmetric Encryption keys themselves.

### Generate production keys

First edit the `symmetric-encryption.yml` configuration file and specify a writable
directory where the files can be written to.

It is recommended that the step below be run on only one of the production servers.
The generated key files must then be copied to all the production servers.

Make sure that the current user has read and write access to the folder listed
in the config file option `key_filename` and `iv_filename`.

To generate the symmetric encryption keys, run the code below in an irb console:

~~~ruby
require 'symmetric-encryption'
SymmetricEncryption.generate_symmetric_key_files('symmetric-encryption.yml', 'production')
~~~

Parameters:

* Filename of the configuration file created above
* Name of the environment to load the configuration for

#### Notes

* Do not run the key generation step more than once, otherwise new keys will be generated
and any encrypted data will no longer be accessible.
* Do not run the key generation step on more than one server in each environment otherwise
each server will be encrypting with its own key and the servers will not be able
to decrypt data encrypted on another server. Just copy the generated files to each server

### Securing the Symmetric Encryption production key files

The encryption key files must _not_ be checked into the source control system
and must be distributed and managed separately from the source code.

The symmetric encryption key consists of the key itself and an optional
initialization vector.

Once the Symmetric Encryption keys have been generated, secure them further by
making the files read-only to the user under which your application will be running and
not readable by any other user.
Change ownership of the keys to your user and only give it access to read the key files:

In the example below, the application will run under the username `jblogs`

    chown jblogs ~/jblogs/.keys/*
    chmod 0400 ~/jblogs/.keys/*

Change `jblogs` above to the userid under which your Ruby processes are run
and update the path to the one supplied in the config file.

When running Ruby servers in a particular environment copy the same
key files to every server in that environment. I.e. All Ruby servers in each
environment must run the same encryption keys.

### Next => [Rake Tasks](rake_tasks.html)
