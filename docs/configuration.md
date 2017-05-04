---
layout: default
---

## Rails Configuration

If deploying to Heroku, see: [Heroku Configuration](heroku.html)

For a standalone environment without Rails, see: [Standalone Configuration](standalone.html)

### Add to Gemfile

Add the following line to your Gemfile _after_ the rails gems:

~~~ruby
gem 'symmetric-encryption'
~~~

Install using bundler:

    bundle

### Creating the configuration file

Generate the configuration file:

    rails generate symmetric_encryption:config /etc/rails/keys

The only parameter is the path where the encrypted key files should be placed,
and is put in the configuration file. The actual files will only be generated in
a step further below.

Note: Ignore the warning about "Symmetric Encryption config not found" since it is
being generated

#### Save to version control

This configuration file should be checked into the source code control system.
It does Not include the Symmetric Encryption keys. They will be generated in the
next step.

### Generating and securing the Symmetric Encryption keys

Once development and testing is complete we need to generate secure encryption
key files for production. It is recommended that the step below be run on only
one of the production servers. The generated key files must then be copied to
all the production web servers.

#### Notes

* Do not run this step more than once, otherwise new keys will be generated
  and any encrypted data will no longer be accessible.

* Do not run this step on more than one server in each environment otherwise
  each server will be encrypting with it's own key and the servers will not be able
  to decrypt data encrypted on another server. Just copy the generated files to each
  server

The symmetric encryption key consists of the key itself and an optional
initialization vector.

To generate the keys run the following Rake task once only in each environment:

    rails generate symmetric_encryption:new_keys production

Replace `production` above as necessary for each environment.

Make sure that the current user has read and write access to the folder listed
in the config file option key_filename.

Note: Ignore the warning about the key files "not found or readable" since they
are being generated

Once the Symmetric Encryption keys have been generated, secure them further by
making the files read-only to the Rails user and not readable by any other user.
Change ownership of the keys to the rails user and only give it access to read the key files:

    chown rails /etc/rails/keys/*
    chmod 0400 /etc/rails/keys/*

Change `rails` above to the userid under which your Rails processes are run
and update the path to the one supplied when generating the config file or
look in the config file itself

When running multiple Rails servers in a particular environment copy the same
key files to every server in that environment. I.e. All Rails servers in each
environment must run the same encryption keys.

Note: The generate step above must only be run once in each environment

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

~~~yaml
#
# Symmetric Encryption for Ruby
#
---
# For the development and test environments the test symmetric encryption keys
# can be placed directly in the source code.
# And therefore no RSA private key is required
development: &development_defaults
  key:    1234567890ABCDEF
  iv:     1234567890ABCDEF
  cipher_name: aes-128-cbc

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
        iv_filename:  /etc/rails/.rails.iv

        # Encryption cipher_name
        #   Recommended values:
        #      aes-256-cbc
        #         256 AES CBC Algorithm. Very strong
        #         Ruby 1.8.7 MRI Approximately 100,000 encryptions or decryptions per second
        #         JRuby 1.6.7 with Ruby 1.8.7 Approximately 22,000 encryptions or decryptions per second
        #      aes-128-cbc
        #         128 AES CBC Algorithm. Less strong.
        #         Ruby 1.8.7 MRI Approximately 100,000 encryptions or decryptions per second
        #         JRuby 1.6.7 with Ruby 1.8.7 Approximately 22,000 encryptions or decryptions per second
        cipher_name:  aes-256-cbc

     -
        # OPTIONAL:
        #
        # Any previous Symmetric Encryption Keys
        #
        # Only used when old data still exists that requires old decryption keys
        # to be used
        key_filename: /etc/rails/.rails_old.key
        iv_filename:  /etc/rails/.rails_old.iv
        cipher_name:  aes-256-cbc
~~~

### Next => [Heroku Configuration](heroku.html)
