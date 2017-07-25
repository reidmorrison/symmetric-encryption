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
      For example `/etc/symmetric-encryption`.
    * This path should be outside of the application and definitely under a 
      path that would _not_ be included in the source control system.
    * Secure the path and generated files so that only the user under which the
      application runs can access them.
    * Move the environment specific key files to their relevant environments
      and then destroy them from development machines.
    * Only used by the file keystore, when using `--heroku` or `--environment` then `--key-path` is not used.
    * If the directory does not exist it will attempt to create it. However, the default of `/etc/symmetric-encryption` 
      is seldom writable by regular user accounts.
    * Default: `/etc/symmetric-encryption`
* `--app-name NAME`
    * Set an application name. 
    * If running rails, recommended to set this to the rails application name.
    * The file keystore uses the app name as part of the file name.
    * The environment keystore uses the app name as part of the environment variable name.
    * Recommed using a lowercase application name.
    * Default: `symmetric-encryption`
* `--envs ENVIRONMENTS`
    * Comma separated list of environments for which to generate the config file. 
    * Default: development,test,release,production
* `--cipher-name NAME`
    * Name of the cipher to use when generating a new config file, or when rotating keys. 
    * Default: `aes-256-cbc` 
* `--config CONFIG_FILE`
    * Path and filename of the generated configuration file.
    * Default: `config/symmetric-encryption.yml`.
* `--keystore [heroku|environment|file]`
    * Specify which keystore to use to hold the encryption keys.
    * Valid values:
        * `heroku`
            * Generate a configuration file for use on heroku.
            * Follow the instructions displayed to store the encrypted encryption key
              as a heroku environment settings.
        * `environment`
            * Generate a configuration file where the encrypted encryption key is held in an environment variable
              instead of using the default file store.
            * Follow the instructions displayed to set the encrypted encryption key in each environment.
        * `file`
            * Stores the encrypted encryption key as files on disk. 
            * See `--key-path` to change the location of the file keystore.
    * Default: `file`

##### Example

It is recommended to run the following commands using the same user that the application will run under. In this
example it will use the user `rails`
Create the directory to act as the file keystore, and lock it down so that :

~~~
sudo mkdir /etc/symmetric-encryption
sudo chown rails /etc/symmetric-encryption
chown rails /etc/rails/keys/*
~~~

Generate file keystore, using an application name of `my_app`. Create keystores for each of the environments 
`development`, `test`, `preprod`, `acceptance`, and `production`.

    symmetric-encryption --generate --app-name my_app --envs "development,test,preprod,acceptance,production"
    
Output

    New configuration file created at: config/symmetric-encryption.yml

The following files were created:

~~~
config/symmetric-encryption.yml

/etc/symmetric-encryption/my_app_preprod_v1.key
/etc/symmetric-encryption/my_app_acceptance_v1.key
/etc/symmetric-encryption/my_app_production_v1.key
~~~

Move the file for each environment to all of the servers for that environment that will be running Symmetric Encryption.
Do not copy all files to every environment since each environment should only be able decrypt data from its own environment.

When running multiple Rails servers in a particular environment copy the same key files to every server in that environment. 
I.e. All Rails servers in each environment must run the same encryption keys.

The file `config/symmetric-encryption.yml` should be stored in the source control system along with the other source code.
Do not store any of the key files in `/etc/symmetric-encryption` in the source control system since they must be kept separate
at all times from the above `config/symmetric-encryption.yml` file.

To meet PCI Compliance the above steps need to be completed by an Operations Administrator and not by a developer
or software engineer. The developers should never have access to the key files, or have copies of them on their machines.

It is recommended to lock down the key files to prevent any other user from being able to read them:
~~~
sudo chmod -R 0400 /etc/symmetric-encryption
~~~
  
##### Heroku Example

Specify Heroku as the keystore so that the encrypted encryption keys can be stored in Heroku instead of in files.

    symmetric-encryption --generate --keystore heroku --app-name my_app --envs "development,test,production"

### Next => [Command Line](cli.html)
