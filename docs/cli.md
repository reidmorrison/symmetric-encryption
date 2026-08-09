---
layout: default
redirect_from:
  - /rake_tasks.html
---

## Command Line
{:.no_toc}

**Contents**

* TOC
{:toc}

The `symmetric-encryption` command generates configuration files and keys, rotates keys, and
encrypts and decrypts files and strings.

~~~
symmetric-encryption --help
~~~

Each environment has its own keys, so most commands must be run in the environment they apply to.
Generating a configuration file and rotating keys are the exceptions: run those once and copy the
result to the environments that need it.

## Step 1: Point it at your configuration

The command reads `config/symmetric-encryption.yml` in the current directory, for the environment in
`SYMMETRIC_ENCRYPTION_ENV`, `RACK_ENV` or `RAILS_ENV`, defaulting to `development`.

Override either per invocation:

~~~
symmetric-encryption --config path/to/symmetric-encryption.yml --env production --decrypt secret.enc
~~~

Or set them in the environment, so they do not have to be repeated:

~~~shell
export SYMMETRIC_ENCRYPTION_CONFIG="~/application/common/config/symmetric-encryption.yml"
export SYMMETRIC_ENCRYPTION_ENV="production"
~~~

## Step 2: Encrypt and decrypt files

~~~
symmetric-encryption --encrypt large_file.csv --output large_file.csv.enc
~~~

Compression is applied by default when encrypting a file. Turn it off with `--no-compress`:

~~~
symmetric-encryption --encrypt photo.jpg --output photo.jpg.enc --no-compress
~~~

Decrypt:

~~~
symmetric-encryption --decrypt large_file.csv.enc --output large_file.csv
~~~

Without `--output`, the result goes to stdout, so an encrypted file can be inspected without ever
writing a decrypted copy to disk:

~~~
symmetric-encryption --decrypt large_file.csv.enc | wc -l
symmetric-encryption --decrypt large_file.csv.enc | grep "Hello"
symmetric-encryption --decrypt large_file.csv.enc | head
~~~

Without a file name, input is read from stdin, so the command composes with a pipeline:

~~~
cat large_file.csv | symmetric-encryption --encrypt --output large_file.csv.enc
~~~

## Step 3: Encrypt strings for configuration files

Prompt for a value, masked, and print its encrypted form:

~~~
symmetric-encryption --encrypt --prompt
~~~

You are asked for the value twice, so a typo cannot be encrypted unnoticed. Decrypt one the same way:

~~~
symmetric-encryption --decrypt --prompt
~~~

Both need the `highline` gem, which is not a dependency of this gem:

~~~ruby
gem "highline"
~~~

Generate a random password and print it with its encrypted form, ready to paste into a
configuration file:

~~~
symmetric-encryption --new-password
symmetric-encryption --new-password 32
~~~

Once keys have been rotated, re-encrypt the values already sitting in your configuration files.
Values that cannot be decrypted in the current environment are left alone:

~~~
symmetric-encryption --re-encrypt "**/*.yml"
~~~

## Step 4: Manage keys

See [Key Rotation](key_rotation.html) for when and why to run these.

~~~
symmetric-encryption --generate --app-name my_app     # New configuration file and keys
symmetric-encryption --rotate-keys                    # New data encryption key
symmetric-encryption --rotate-kek                     # New key encrypting keys only
symmetric-encryption --activate-key                   # Make the highest version primary
symmetric-encryption --cleanup-keys                   # Remove all but the highest version
~~~

`--cleanup-keys` names the versions it is about to remove and asks before removing them, because
data encrypted with a removed key can no longer be read. Use `--force` to skip the prompt in a
script. When stdin is not a terminal it does not prompt at all, but it still names the versions.

## Option reference

### Files and strings

| Option | Description |
|---|---|
| `-e`, `--encrypt [FILE]` | Encrypt a file, or read from stdin when no file is supplied. |
| `-d`, `--decrypt [FILE]` | Decrypt a file, or read from stdin when no file is supplied. |
| `-o`, `--output FILE` | Write the result to this file. Default: stdout. |
| `-P`, `--prompt` | Prompt for a string to encrypt or decrypt instead of using a file. |
| `-z`, `--compress` | Compress the output. Default when encrypting files. |
| `-Z`, `--no-compress` | Do not compress. Default when encrypting strings. |
| `-n`, `--new-password [SIZE]` | Generate a random URL-safe base64 password. Default size: 22. |
| `-r`, `--re-encrypt [PATTERN]` | Re-encrypt matching files. Default: `**/*.{yml,rb}` |
| `-V`, `--key-version NUMBER` | Cipher version to encrypt or re-encrypt with. Default: the primary cipher. |

### Configuration and keys

| Option | Description |
|---|---|
| `-g`, `--generate` | Generate a new configuration file and keys for every environment. |
| `-s`, `--keystore NAME` | `file`, `environment`, `heroku`, `aws` or `gcp`. Default: `file`. |
| `-a`, `--app-name NAME` | Application name, used in key file and variable names. Default: `symmetric-encryption`. |
| `-S`, `--environments LIST` | Comma separated. Default: `development,test,release,production`. |
| `-C`, `--cipher-name NAME` | Default: `aes-256-gcm`. |
| `-K`, `--key-path PATH` | Where key files are written. Default: `~/.symmetric-encryption`. |
| `--key-permissions LIST` | Octal permissions the generated key files may have. Default: `0600,0400`. |
| `-B`, `--regions LIST` | AWS KMS regions to encrypt the data key with. |
| `-m`, `--migrate` | Migrate an older configuration file to the current format. |

### Key rotation

| Option | Description |
|---|---|
| `-R`, `--rotate-keys` | Generate a new key version and update the configuration file. |
| `-U`, `--rotate-kek` | Replace the key encrypting keys only; the data encryption key is unchanged. |
| `-D`, `--rolling-deploy` | Add the new key second so it can be deployed before it is activated. |
| `-A`, `--activate-key` | Move the highest version key to the top, making it the primary. |
| `-X`, `--cleanup-keys` | Remove every key except the highest version. |
| `--force` | Do not ask before removing keys with `--cleanup-keys`. |

### General

| Option | Description |
|---|---|
| `-c`, `--config PATH` | Configuration file. Default: `config/symmetric-encryption.yml`. |
| `-E`, `--env NAME` | Environment to use from the configuration file. |
| `-L`, `--ciphers` | List the OpenSSL ciphers available on this machine. |
| `-v`, `--version` | Print the Symmetric Encryption and OpenSSL versions. |
| `-h`, `--help` | Print the full option list. |

## Next steps

* [Key Rotation](key_rotation.html): introducing a new key without downtime.
* [Configuration](configuration.html): the configuration file and the keystores.
* [Files](files.html): the same operations from Ruby.
