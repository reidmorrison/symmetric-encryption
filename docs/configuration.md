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
        * `gcp`
            * Generate a configuration file for use with the [Google Cloud Platform KMS](https://cloud.google.com/kms/).
            * See instructions below on setting up access credentials and settings.
    * Default: `file`
* `--regions`
    * Used by the `aws` keystore to set the regions that should be supported.
    * Default: `us-east-1,us-east-2,us-west-1,us-west-2`

### File Keystore

Create the directory where the output files will be created and secure it so that no other users can see the files:

~~~
mkdir ~/.symmetric-encryption
~~~

Once you have generated the configuration files, you will want to change the permissions on this directory; however,
do not do this until **after** you've run the `symmetric-encryption` command:

~~~
chmod -R 0400 ~/.symmetric-encryption
~~~

If you see a "Permission denied" error when running `symmetric-encryption`, confirm that you have the ability to read, 
write, and access (i.e. execute) the directory.

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
If you generated your keys on a development machine, you may need to edit the `symmetric-encryption.yml` file to
change the `file_name` path to reflect where the key files reside on each server.

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

#### Key file permissions and ownership

Symmetric Encryption refuses to read a key file that other users on the machine can read, since
anyone who can read the key file can decrypt everything that was encrypted with it. By default a
key file has to be `0600` or `0400`, and has to be owned by the user running the application.

Some environments dictate the permissions and the ownership of the key file, and cannot be asked
for `0600` owned by the application user. The most common one is a Kubernetes secret volume mounted
with `readOnly: true`, which mounts its files as `0644` owned by `root`, whatever user the container
itself runs as. Supply the permissions, the owner, and the group that those key files will have and
Symmetric Encryption verifies against those instead of the defaults:

~~~yaml
production:
  ciphers:
    - key_filename: /etc/keys/my_app_production_v1.encrypted_key
      permissions: "0644"
      owner: root
      group: root
      iv: aFhScC9maXNHTFhBaFZjS3M=
      key_encrypting_key:
        encrypted_key: TWpBeE9UQXhNRE10TWpFNU1UUTVMVGM9
        iv: WVRJNU1UUTVMVGM1TFRJd01UZz0=
        key_encrypting_key:
          key_filename: /etc/keys/my_app_production_v1.kekek
          permissions: "0644"
          owner: root
          group: root
          iv: TVRrMk1UUTVMVGM1TFRJd01UZz0=
~~~

Notes:

* All three apply to one key file, so supply them for every `key_filename` entry, including the
  key encrypting key files nested below it. Generate a configuration with the permissions already in
  place, and key files already created with them, using `--key-permissions`:

      symmetric-encryption --generate --app-name my_app --key-permissions 0644

  `--rotate-keys` and `--rotate-kek` carry all three settings into the entries they write, so they
  only have to be supplied once. There is no equivalent option for `owner` and `group`, because
  `symmetric-encryption` cannot give a file away to another user. Add them to the configuration
  file by hand: they describe the environment the key files are deployed into, not the machine the
  keys were generated on.
* Supply `permissions` as an octal file mode without the file type bits, either as a String,
  `"0644"`, or as an Integer, `0644`.
* Supply `owner` and `group` as a name, `root`, or as a numeric id, `0`. Use the numeric id when the
  name does not resolve on every machine that loads this configuration.
* `owner` replaces the default check that the key file is owned by the user running the application.
  `group` adds a check that is not performed at all by default. Naming them is not the same as
  skipping them, the key file still has to match what the configuration says.
* Supply a list to any of them when more than one value is acceptable. New key files are created
  with the first permission in the list, so list the most restrictive one first:

  ~~~yaml
    - key_filename: /etc/keys/my_app_production_v1.encrypted_key
      permissions:
        - "0600"
        - "0644"
      owner:
        - deploy
        - root
  ~~~

* The configuration file is evaluated with ERB, so a value can come from the environment when it
  differs per deployment: `permissions: "<%= ENV['KEY_FILE_PERMISSIONS'] %>"`.
* Only relax these where something outside of the application controls the key file and the
  surrounding environment supplies the protection instead. On a shared machine, widening the
  permissions lets every other user on it read the encryption key.

### Heroku Keystore

Specify Heroku as the keystore so that the encrypted encryption keys can be stored in Heroku instead of in files.

    symmetric-encryption --generate --keystore heroku --app-name my_app --environments "development,test,production"

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

#### Generating new data keys:

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

### Google Cloud Platform KMS

Symmetric Encryption can use the Google Cloud Platform [Key Management Service (KMS)](https://cloud.google.com/kms) to hold and manage the Key Encrypting Key.

Symmetric Encryption expects that you have already created a key and a keyring in GCP KSM. It is expected that the keyring name matches your application name and that your key name matches your environment name.

#### GCP KMS Dependencies

The GCP KMS gem is a soft dependency, which is only required when the GCP KMS keystore is being used by
Symmetric Encryption. Add the following line to Gemfile when using bundler:

    gem 'google-cloud-kms'

If not using Bundler, run the following from the command line:

    gem install google-cloud-kms

#### Setting up the GCP Credentials:

You're expected to have a service account with permissions for encryption/decryption using GCP KMS keys. Follow the GCP instructions for [creating and setting credentials](https://cloud.google.com/docs/authentication/getting-started#auth-cloud-implicit-ruby).

#### Setting GCP environment variables

You have to set `GOOGLE_CLOUD_PROJECT` environment variable to the value of your project id at GCP console.

There is also an optional variable `GOOGLE_CLOUD_LOCATION` which can be set to your key location. If not set it is assumed that your key location is `global`.

#### Generating a key

You can generate a new key with the following command:

    symmetric-encryption --generate --keystore gcp --app-name my_app --environments "development,test,production"

### Next => [Command Line](cli.html)
