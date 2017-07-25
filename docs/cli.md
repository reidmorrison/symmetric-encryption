---
layout: default
---

## Command Line Interface

Symmetric Encryption v4 now uses a standalone command line interface to:
* Encrypt files
* Decrypt files
* Generate new passwords
* Generate a new configuration file
* Perform Key rotation

If running Symmetric Encryption v3 or earlier, instead use: [Rake Tasks](rake_tasks.html)

For the complete list of commands run:

    symmetric-encryption --help

Since each environment has its own encryption keys it is necessary to run the these commands in the corresponding
environment. However, this does not apply to generating the configuration file and to key rotation which can be
run once in one environment and then moved/copied to the relevant environments.

#### Examples

Encrypt a file:

    symmetric-encryption --encrypt large_file.csv --output large_file.csv.enc

Encrypt and compress a file (_Recommended_):

    symmetric-encryption --encrypt large_file.csv --output large_file.csv.enc --compress

Decrypt a file:

    symmetric-encryption --decrypt large_file.csv.enc --output large_file.csv
    
Count the lines in an encrypted file, without creating an unencrypted copy on disk:

    symmetric-encryption --decrypt large_file.csv.enc | wc -l

Search for lines in an encrypted file, without creating an unencrypted copy on disk:

    symmetric-encryption --decrypt large_file.csv.enc | grep "Hello"

Display the first few lines in an encrypted file, without creating an unencrypted copy on disk:

    symmetric-encryption --decrypt large_file.csv.enc | head

Display the last few lines in an encrypted file, without creating an unencrypted copy on disk:

    symmetric-encryption --decrypt large_file.csv.enc | tail

Generate a random password and display its encrypted form for use in config files, etc.:

    symmetric-encryption --new-password

Prompt to enter a masked string and then encrypt it:

    symmetric-encryption --encrypt --prompt
    
Prompt to enter an encrypted string and then decrypt it:

    symmetric-encryption --decrypt --prompt
    
#### Notes

##### Highline

For the `--prompt` option above to work, the `highline` gem must be added to `Gemfile` first and
then installed by running `bundle.

~~~ruby
gem install 'highline'
~~~

##### Specify configuration file location

If the Symmetric Encryption configuration file has a different name or is stored in a directory other than
the standard `config/symmetric-encryption.yml`, then it can be set using the environment variable 
`SYMMETRIC_ENCRYPTION_CONFIG`.

For example set the location of the Symmetric Encryption config file:
~~~shell
# Specify Symmetric Encryption config file so that it does not need to be specified at the command line every time.
export SYMMETRIC_ENCRYPTION_CONFIG="~/application/common/config/symmetric-encryption.yml"
~~~

### Next => [Key Rotation](key_rotation.html)
