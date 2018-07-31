---
layout: default
---

## Configuration

If running Symmetric Encryption v3, see [v3 Configuration](v3_configuration.html)

The notes below apply to Symmetric Encryption v4 and above.

### Add to Gemfile

Add the following line to your Gemfile _after_ the rails gems:

~~~ruby
gem 'symmetric-encryption'
~~~

Install using bundler:

    bundle

### Creating the configuration file

Generate the configuration file and encryption keys for every environment:

    symmetric-encryption --generate

Options:
* `--key-path OUTPUT_PATH`
    * The path where the encrypted key files should be written to.
    * This path should be outside of the application and definitely under a
      path that would _not_ be included in the source control system.
    * Secure the path and generated files so that only the user under which the
      application runs can access them.
    * Move the environment specific key files to their relevant environments
      and then destroy them from development machines.
    * Ignored when using the `--heroku` or `--environment` keystores.
    * If the directory does not exist it will attempt to create it.
    * Default: `~/.symmetric-encryption`
* `--app-name NAME`
    * Set an application name.
    * If running rails, recommended to set this to the rails application name.
    * The file keystore uses the app name as part of the file name.
    * The environment keystore uses the app name as part of the environment variable name.
    * Recommend using a lowercase application name.
    * Default: `symmetric-encryption`
* `--environments ENVIRONMENTS`
    * Comma separated list of environments for which to generate the config file.
    * Default: `development,test,release,production`
* `--cipher-name NAME`
    * Name of the cipher to use when generating a new config file, or when rotating keys.
    * Default: `aes-256-cbc`
* `--config CONFIG_FILE`
    * Path and filename of the generated configuration file.
    * Default: `config/symmetric-encryption.yml`.
* `--keystore [aws|environment|file|heroku]`
    * Specify which keystore to use to hold the encryption keys.
    * Valid values:
        * `aws`
            * Generate a configuration file for use with the [AWS Key Management Service](https://aws.amazon.com/kms/).
            * See instructions below on setting up the AWS Credentials prior to generating or rotating encryption keys.
        * `environment`
            * Generate a configuration file where the encrypted encryption key is held in an environment variable
              instead of using the default file store.
            * Follow the instructions displayed to set the encrypted encryption key in each environment.
        * `file`
            * Stores the encrypted encryption key as files on disk.
            * See `--key-path` to change the location of the file keystore.
        * `heroku`
            * Generate a configuration file for use on heroku.
            * Follow the instructions displayed to store the encrypted encryption key
              as a heroku environment settings.
    * Default: `file`
* `--regions`
    * Used by the `aws` keystore to set the regions that should be supported.
    * Default: `us-east-1,us-east-2,us-west-1,us-west-2`

### File Keystore

Create the directory where the output files will be created and secure it so that no other users can see the files:

~~~
mkdir ~/.symmetric-encryption
chmod -R 0400 ~/.symmetric-encryption
~~~

Generate file keystore, using an application name of `my_app`. Create keystores for each of the environments
`development`, `test`, `preprod`, `acceptance`, and `production`.

    symmetric-encryption --generate --app-name my_app --environments "development,test,preprod,acceptance,production"

Output

    New configuration file created at: config/symmetric-encryption.yml

The following files were created:

~~~
config/symmetric-encryption.yml

~/.symmetric-encryption/my_app_preprod_v1.key
~/.symmetric-encryption/my_app_acceptance_v1.key
~/.symmetric-encryption/my_app_production_v1.key
~~~

Move the file for each environment to all of the servers for that environment that will be running Symmetric Encryption.
Do not copy all files to every environment since each environment should only be able decrypt data from its own environment.

When running multiple Rails servers in a particular environment copy the same key files to every server in that environment.
I.e. All Rails servers in each environment must run the same encryption keys.

The file `config/symmetric-encryption.yml` should be stored in the source control system along with the other source code.
Do not store any of the key files in `~/.symmetric-encryption` in the source control system since they must be kept separate
at all times from the above `config/symmetric-encryption.yml` file.

To meet PCI Compliance the above steps need to be completed by an Operations Administrator and not by a developer
or software engineer. The developers should never have access to the key files, or have copies of them on their machines.

It is recommended to lock down the key files to prevent any other user from being able to read them:
~~~
chmod -R 0400 ~/.symmetric-encryption
~~~

### Heroku Keystore

Specify Heroku as the keystore so that the encrypted encryption keys can be stored in Heroku instead of in files.

    symmetric-encryption --generate --keystore heroku --app-name my_app --envs "development,test,production"
    
### AWS KMS keystore

Symmetric Encryption can use the [AWS Key Management Service (KMS)](https://aws.amazon.com/kms/) to hold and manage
the Key Encrypting Key (Customer Master Key).

This is the most secure keystore that Symmetric Encryption currently supports. By storing the master key
in AWS KMS it cannot be read or exported, only used to encrypt or decrypt the data encryption keys. The encrypted
data encryption key is stored locally on the file system since it has been secured by encrypting it with the 
AWS KMS Customer Master key.

Symmetric Encryption creates a new Customer Master Key in AWS KMS in every AWS Region and for every environment 
so that they can be managed and rotated directly from within the AWS KMS management interface.

#### AWS Dependencies

The AWS KMS gem is a soft dependency, which is only required when the AWS KMS keystore is being used by
Symmetric Encryption. Add the following line to Gemfile when using bundler:

    gem 'aws-sdk-kms'

If not using Bundler, run the following from the command line:

    gem install aws-sdk-kms
    
#### Setting up the AWS Credentials:

In order to create new keys, or to rotate new keys using the AWS KMS, it is necessary to create the necessary
AWS Credentials.

It is recommended to use a separate _management_ AWS KMS credential to manage the keys. These credentials should
be granted access to all KMS operations. See Access Control below for securing runtime privileges by environment.

Follow the AWS instructions for [creating and setting the AWS credentials](https://docs.aws.amazon.com/sdk-for-ruby/v3/developer-guide/setup-config.html) 

#### Setting up the AWS Credentials:

Once the AWS _management_ credentials have been created and set, the new keys can now be generated.

When new keys are generated or rotated, they will be encrypted with the master key for every region
specified. This allows data to be encrypted in one region and to be decrypted in another region during a disaster
scenario.

By default the following regions are configured: `us-east-1,us-east-2,us-west-1,us-west-2`

The configured regions can be overriden by setting the `--regions` flag above.

Example: Generate New Keys for the first time, targeting the AWS keystore:

    symmetric-encryption --generate --keystore aws --app-name my_app --environments "development,test,production"

Example:  Rotate existing keys migrating to AWS for the new keys:

    symmetric-encryption --rotate-keys --keystore aws --app-name my_app --environments production

Once the new keys have been generated, they should be moved to the relevant servers. By default the files
are generated in `~/.symmetric-encryption` unless the flag `--key-path` was used to change the path.

#### Setting a Region

The AWS region must be set on every server that uses Symmetric Encryption so that it uses the AWS KMS service
in that region.

The simplest way to set the region is to set the `AWS_REGION` environment variable.

    export AWS_REGION=us-west-2
    
See the AWS documentation for more options in [setting the AWS Region](https://docs.aws.amazon.com/sdk-for-ruby/v3/developer-guide/setup-config.html).

#### Access Control

Each environment should have its own credentials and those credentials should be restricted to decrypting using 
the Customer Master Key (CMK) for that environment only. This prevents different environments from being able 
to decrypt the data encryption key (DEK) from another environment.

For each key, in each region change the permissions on the key itself so that only that environment's 
AWS API user can access that key. For example, create a user `rails_release` for the release environment 
and limit it to decrypt authorization on the `release` key.

### Next => [Command Line](cli.html)
