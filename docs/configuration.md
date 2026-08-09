---
layout: default
redirect_from:
  - /heroku.html
  - /standalone.html
  - /v3_configuration.html
---

## Configuration
{:.no_toc}

**Contents**

* TOC
{:toc}

There are two things to configure: **which ciphers** an environment uses, and **where their keys
live**. The first goes in `config/symmetric-encryption.yml`, which belongs in source control. The
second is a keystore, and the key itself never goes into source control.

Start at Step 1 and stop when your setup works. Most applications never get past Step 4.

## Step 1: Add the gem

~~~ruby
gem "symmetric-encryption"
~~~

In Rails, add it *after* the rails gems. Then:

~~~
bundle install
~~~

## Step 2: Generate the configuration and keys

~~~
symmetric-encryption --generate --app-name my_app
~~~

~~~
New configuration file created at: config/symmetric-encryption.yml
~~~

Useful options:

* `--app-name NAME` — used in key file names and environment variable names. In Rails, use the
  application name, lowercase. Default: `symmetric-encryption`
* `--environments LIST` — comma separated. Default: `development,test,release,production`
* `--key-path PATH` — where key files are written. Default: `~/.symmetric-encryption`
* `--keystore NAME` — one of `file`, `environment`, `heroku`, `aws`, `gcp`. Default: `file`
* `--cipher-name NAME` — Default: `aes-256-gcm`, which is authenticated: it detects any change
  to an encrypted value rather than decrypting whatever it is given. See
  [Security](security.html). Supply `aes-256-cbc` for the unauthenticated cipher used before v5.
* `--config PATH` — Default: `config/symmetric-encryption.yml`
* `--regions LIST` — AWS KMS only. Default: `us-east-1,us-east-2,us-west-1,us-west-2`

Every option is listed on the [Command Line](cli.html) page.

## Step 3: Understand what was generated

A configuration file has one entry per environment, and each entry lists one or more ciphers:

~~~yaml
development:
  ciphers:
  - key: 1234567890ABCDEF
    iv: 1234567890ABCDEF
    cipher_name: aes-128-cbc
    version: 1
test:
  ciphers:
  - key: 1234567890ABCDEF
    iv: 1234567890ABCDEF
    cipher_name: aes-128-cbc
    version: 1
production:
  ciphers:
  - keystore: :file
    cipher_name: aes-256-gcm
    version: 1
    key_filename: /home/deploy/.symmetric-encryption/my_app_production_v1.encrypted_key
    iv: !binary |-
      k7jzJiVAWfUTCcJd2QXr8A==
    key_encrypting_key:
      encrypted_key: !binary |-
        WTfUx7X3WiwJ8zWqC+0wnCzhxngB7/RSrKWhrMFyykQ=
      iv: !binary |-
        igiEwwHM8ukpX3zwQT+LDw==
~~~

Three things are worth noticing.

**Development and test hold their key in the file itself.** That key is the same in every generated
configuration file and is published in this documentation, so it is not a secret. It means a new
developer needs no key files to run the application or its test suite. Never put private data through
those environments.

**The keystore is a per environment setting.** One configuration file can use a different keystore in
every environment. There is nothing to merge by hand.

**The first cipher encrypts; the rest only decrypt.** New values are always encrypted with the first
cipher in the list. The others exist so that data encrypted by earlier keys can still be read. This
is what makes [key rotation](key_rotation.html) possible.

## Step 4: Deploy the keys

The generated files divide in two, and keeping them apart is the whole point:

| File | Source control | Deployed to |
|---|---|---|
| `config/symmetric-encryption.yml` | **Yes** | Every environment |
| `~/.symmetric-encryption/my_app_production_v1.encrypted_key` | **Never** | Production servers only |

Deploy each environment's key file only to that environment's servers, so that one environment cannot
decrypt another's data. Every server *within* an environment gets the same key file.

Lock the key files down. Symmetric Encryption refuses to read a key file that other users on the
machine can read:

~~~
chmod -R 0400 ~/.symmetric-encryption
~~~

Do this **after** running `symmetric-encryption`, not before, or generation cannot write the files.

To meet PCI compliance these steps are performed by an operations administrator, not by a developer.
Developers should never have copies of production key files. See [Security](security.html).

### Loading the configuration

In Rails there is nothing to do. The railtie loads the configuration during boot, in
`before_configuration`, deliberately earlier than Active Record so that `database.yml` can itself
contain an encrypted password.

Outside Rails, load it yourself:

~~~ruby
require "symmetric_encryption"

SymmetricEncryption.load!("config/symmetric-encryption.yml", "production")
~~~

Two environment variables override the defaults, in Rails and out of it:

* `SYMMETRIC_ENCRYPTION_CONFIG` — path to the configuration file.
* `SYMMETRIC_ENCRYPTION_ENV` — which environment entry to load. Useful when several deployments run
  with `RAILS_ENV=production` but each needs its own key.

## Keystores

### File keystore

The default. The data encryption key lives in a file on disk, itself encrypted by a key encrypting
key. Suitable for any environment where you control the file system.

~~~
mkdir ~/.symmetric-encryption
symmetric-encryption --generate --app-name my_app --environments "development,test,preprod,production"
~~~

Generated:

~~~
config/symmetric-encryption.yml

~/.symmetric-encryption/my_app_preprod_v1.encrypted_key
~/.symmetric-encryption/my_app_production_v1.encrypted_key
~~~

If you generated the keys on a development machine, edit `symmetric-encryption.yml` so that
`key_filename` points at wherever the key files actually live on each server.

If you see a "Permission denied" error when running `symmetric-encryption`, confirm you can read,
write, and access (that is, execute) the directory.

#### Key file permissions and ownership

Symmetric Encryption refuses to read a key file that other users on the machine can read, since
anyone who can read the key file can decrypt everything that was encrypted with it. By default a key
file has to be `0600` or `0400`, and has to be owned by the user running the application.

Some environments dictate the permissions and ownership of the key file and cannot be asked for
`0600` owned by the application user. The most common is a Kubernetes secret volume mounted with
`readOnly: true`, which mounts its files as `0644` owned by `root`, whatever user the container runs
as. Supply the permissions, owner, and group those key files will have, and Symmetric Encryption
verifies against those instead of the defaults:

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

* All three apply to one key file, so supply them for every `key_filename` entry, including the key
  encrypting key files nested below it. Generate a configuration with the permissions already in
  place using `--key-permissions`:

      symmetric-encryption --generate --app-name my_app --key-permissions 0644

  `--rotate-keys` and `--rotate-kek` carry all three settings into the entries they write, so they
  only have to be supplied once. There is no equivalent option for `owner` and `group`, because
  `symmetric-encryption` cannot give a file away to another user. Add them by hand: they describe the
  environment the key files are deployed into, not the machine the keys were generated on.
* Supply `permissions` as an octal file mode without the file type bits, either as a String,
  `"0644"`, or as an Integer, `0644`.
* Supply `owner` and `group` as a name, `root`, or as a numeric id, `0`. Use the numeric id when the
  name does not resolve on every machine that loads this configuration.
* `owner` replaces the default check that the key file is owned by the user running the application.
  `group` adds a check that is not performed at all by default. Naming them is not the same as
  skipping them: the key file still has to match what the configuration says.
* Supply a list when more than one value is acceptable. New key files are created with the first
  permission in the list, so list the most restrictive one first:

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
* Only relax these where something outside the application controls the key file and the surrounding
  environment supplies the protection instead. On a shared machine, widening the permissions lets
  every other user read the encryption key.
* The same three settings apply to the AWS KMS and Google Cloud KMS keystores, which also hold their
  encrypted data encryption key in a local file. Supply them alongside `key_files` or `key_file`:

  ~~~yaml
  production:
    ciphers:
      - keystore: aws
        master_key_alias: alias/symmetric-encryption/my_app/production
        permissions: "0644"
        owner: root
        group: root
        key_files:
          - region: us-east-1
            file_name: /etc/keys/my_app_production_us-east-1_v1.encrypted_key
          - region: us-west-2
            file_name: /etc/keys/my_app_production_us-west-2_v1.encrypted_key
  ~~~

  One entry covers every region, since those key files are all created the same way.

### Environment variable keystore

Holds the encrypted encryption key in an environment variable instead of a file. For platforms with
no writable file system, or where secrets are injected as environment variables.

~~~
symmetric-encryption --generate --keystore environment --app-name my_app
~~~

The command prints the `export` line to set in each environment. Nothing is written for you: setting
the variable is the deploy's job, which is the point.

### Heroku keystore

The same as the environment keystore, with Heroku-shaped instructions:

~~~
symmetric-encryption --generate --keystore heroku --app-name my_app --environments "development,test,production"
~~~

Follow the displayed `heroku config:add` instructions to set the encrypted encryption key for each
environment.

When several Heroku applications run with `RAILS_ENV=production` and each needs its own encryption
key, name the Symmetric Encryption environment separately:

~~~
heroku config:add SYMMETRIC_ENCRYPTION_ENV=release
~~~

`SYMMETRIC_ENCRYPTION_ENV` selects which entry of `symmetric-encryption.yml` is loaded and leaves
`RAILS_ENV` alone, so Rails still applies its production settings. The `symmetric-encryption` command
honors the same variable when generating or rotating keys.

### AWS KMS

The most secure keystore supported. The master key lives in
[AWS KMS](https://aws.amazon.com/kms/) and cannot be read or exported, only used to encrypt and
decrypt data encryption keys. The encrypted data encryption key is stored locally, safe because only
KMS can unlock it.

Symmetric Encryption creates a Customer Master Key in every configured region and for every
environment, so they can be managed and rotated from the AWS KMS console.

**Dependency.** A soft dependency, only needed when this keystore is used:

~~~ruby
gem "aws-sdk-kms"
~~~

**Credentials.** Use a separate *management* credential, granted access to all KMS operations, to
create and rotate keys. Follow the AWS instructions for
[creating and setting AWS credentials](https://docs.aws.amazon.com/sdk-for-ruby/v3/developer-guide/setup-config.html).

**Generate:**

~~~
symmetric-encryption --generate --keystore aws --app-name my_app --environments "development,test,production"
~~~

New keys are encrypted with the master key in every configured region, so data encrypted in one
region can be decrypted in another during a disaster. Default regions:
`us-east-1,us-east-2,us-west-1,us-west-2`, overridden with `--regions`.

**Migrate an existing configuration to AWS:**

~~~
symmetric-encryption --rotate-keys --keystore aws --app-name my_app --environments production
~~~

**Rotate an existing AWS configuration:**

~~~
symmetric-encryption --rotate-keys --app-name my_app --environments production
~~~

When rotating an existing AWS KMS configuration, the new data key is encrypted for the same regions
as the current key files, and the new key files are written to the same path. Supply `--regions` or
`--key-path` to change either.

**Set the region** on every server, so the right KMS endpoint is used:

~~~
export AWS_REGION=us-west-2
~~~

**Access control.** Each environment should have its own credentials, restricted to decrypting with
the Customer Master Key for that environment only, so one environment cannot decrypt another's data
encryption key. For each key in each region, restrict the key policy to that environment's AWS API
user: create a user `rails_release` for the release environment and limit it to decrypt authorization
on the `release` key.

### Google Cloud KMS

Uses Google Cloud [KMS](https://cloud.google.com/kms) to hold the key encrypting key.

Symmetric Encryption expects the key and keyring to exist already, with the **keyring named after
your application** and the **key named after your environment**.

**Dependency:**

~~~ruby
gem "google-cloud-kms"
~~~

**Credentials.** A service account with encrypt and decrypt permission on the KMS key. Follow the GCP
instructions for
[creating and setting credentials](https://cloud.google.com/docs/authentication/getting-started#auth-cloud-implicit-ruby).

**Environment variables:**

* `GOOGLE_CLOUD_PROJECT` — required, your GCP project id.
* `GOOGLE_CLOUD_LOCATION` — optional, defaults to `global`.

**Generate:**

~~~
symmetric-encryption --generate --keystore gcp --app-name my_app --environments "development,test,production"
~~~

## Supplying the key in the configuration file

The key can be supplied directly in the configuration file, which is how `development` and `test` are
generated, and is usually how existing keys are carried over when migrating an application:

~~~yaml
development:
  ciphers:
    - key: 1234567890ABCDEF
      iv: 1234567890ABCDEF
      cipher_name: aes-128-cbc
      version: 1
~~~

Only do this where the configuration file itself is not a secret. Anyone who can read the file can
decrypt everything encrypted with that key, so use a keystore in production.

`key` and `iv` are raw binary data, not text, and each has to be *exactly* the number of bytes that
`cipher_name` requires:

| `cipher_name` | `key`    | `iv`     |
|---------------|----------|----------|
| `aes-128-cbc` | 16 bytes | 16 bytes |
| `aes-192-cbc` | 24 bytes | 16 bytes |
| `aes-256-cbc` | 32 bytes | 16 bytes |
| `aes-256-gcm` | 32 bytes | not used |

A random binary key cannot be written into YAML as an ordinary quoted string. Most of its bytes are
not printable, and an escape such as `"\xB1"` is read back as the *character* `U+00B1`, which is two
bytes in UTF-8 rather than the single byte intended. Base64 encode the key instead and let YAML decode
it back to binary with its `!!binary` tag:

~~~yaml
development:
  ciphers:
    - key: !!binary |
        scfTCGywW1BWprMPXlUYDOxvso7xZQ3tlJR3h9qViMI=
      iv: !!binary |
        8FOTJUJAbbd/Ovy7163hOQ==
      cipher_name: aes-256-cbc
      version: 1
~~~

To move a hex encoded key into the configuration file, convert it to the base64 that `!!binary`
expects:

~~~ruby
require "base64"

puts Base64.strict_encode64(["b1c7d3086cb05b5056a6b30f5e55180cec6fb28ef1650ded94947787da9588c2"].pack("H*"))
# => scfTCGywW1BWprMPXlUYDOxvso7xZQ3tlJR3h9qViMI=
~~~

When a key or iv is not the right length, loading the configuration raises an `ArgumentError` naming
the cipher and the number of bytes supplied. Never truncate a key to make that error go away: a
truncated key is a *different* key, and nothing already encrypted can be read with it.

## Cipher options

Options that can be set on any cipher entry:

* `cipher_name` — the OpenSSL cipher. `symmetric-encryption --generate` writes `aes-256-gcm`.
  Defaults to `aes-256-cbc` when a cipher entry leaves it out, so that a configuration written
  before v5 still reads the data it encrypted. See [Security](security.html).
* `version` — 0 to 255. Identifies this key in the header of every value it encrypts.
* `always_add_header` — whether to add the header when nothing else requires it. Default: `true`, and
  strongly recommended, since it is what makes key rotation work.
* `encoding` — how the binary result is encoded. One of `base64strict` (default), `base64`,
  `base64urlsafe`, `base16`, `none`.

Every cipher in one configuration file has to use an encoding the others can read, since a value is
decoded with the primary cipher's encoder before its header says which cipher encrypted it. Only
`base64` and `base64strict` can be mixed with each other; loading a configuration that mixes anything
else raises.

## Next steps

* [Command Line](cli.html): every option of the `symmetric-encryption` command.
* [Key Rotation](key_rotation.html): introducing a new key without downtime.
* [Security](security.html): authenticated encryption, threat model, and PCI compliance.
* [Guide](guide.html): using the library once it is configured.
