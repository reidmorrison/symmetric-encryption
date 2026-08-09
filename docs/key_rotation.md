---
layout: default
redirect_from:
  - /multiple_ciphers.html
---

## Key Rotation
{:.no_toc}

**Contents**

* TOC
{:toc}

According to the PCI Compliance documentation: "Cryptographic keys must be changed on an annual basis."

During the transition period of moving from one encryption key to another symmetric-encryption supports multiple 
Symmetric Encryption keys. Since every encrypted value has a header that contains the version number of the key
that was used to encrypt it, that key will be used to decrypt it, even though a new key is already active and
is being used to encrypt new values.

The active key is the first key in the list in `symmetric-encryption.yml`. Other keys are only used to decrypt
values that were encrypted with those keys.

Encryption keys are secured (encrypted) using a Key Encryption Key (RSA Private key). New keys are secured using the
same Key Encryption Key, so that multiple encryption keys can be secured at the same time.


## Recommended steps

Below are the recommended steps to perform "hot" key rotation, so that the encryption key can be changed without
requiring system downtime or maintenance window.

The steps can be reduced if they are being performed during a maintenance window. In this case do not supply
the `--deploy` option below so that new key will be active immediately, and skip step 4 below.

## Step 1: Add the new key as secondary key

During a rolling deploy it is possible for servers to encrypt data using a new
key before the other servers have been updated. This would result in cipher
errors should any of the servers try to decrypt the data since they do not have
the new key.

To avoid this race-condition add the new key as the second key in the configuration
file. That way it will continue decrypting using the current key, but can also
decrypt with the new key during the rolling deploy.

For example, with Symmetric Encryption v4, use the command line interface to update the config file 
and generate the new keys:

    symmetric-encryption --rotate-keys --rolling-deploy  --app-name my_app

The `--rolling-deploy` option stores the new key as the second key so that it will not be activated yet.

Replace `my_app` with the name of the application that is going to use this key. Recommend using lower case.

By default a new key is generated for every environment, to limit it to just production:

    symmetric-encryption --rotate-keys --rolling-deploy  --app-name my_app --environments production
    
The command names the environments it rotated. Development and test hold their key in the configuration file
itself, so there is no keystore to generate a new key from and they are left unchanged.

Copy the key file to every server in that particular environment that runs the application or uses Symmetric Encryption.

If the keys for multiple environments are generated above, then move the relevant key files to the servers for that environment.

New key files are written alongside the current ones, wherever the configuration file says they are. Supply
`--key-path` to write them somewhere else. By default the key files are located in `/etc/symmetric-encryption`.

    
## Step 2: Re-encrypt all passwords in the source repository

Passwords, such as those for the database, need to be re-encrypted using the new key.
Scan the source code repository for YAML files or other files that contain any encrypted passwords or
other encrypted values.

Since the new key is the secondary key, its version must be supplied when re-encrypting.

For example, with Symmetric Encryption v4, re-encrypt yaml files:

    symmetric-encryption --re-encrypt --key-version 5
    
Where key-version `5` above must be the version of the new key generated above.

Note:
* Since the keys for each environment are different, the above step must be run in each
  environment and then the modified files committed back into version control. 
    
## Step 3: Deploy

Deploy the updated source code to each environment so that the new key is available to all
servers for decryption purposes.

## Step 4: Activate the new key

Once the new key has been deployed as a secondary key, the next deploy can move
the new key to the top of the list so that it will be the active key for encrypting new data.
The previous key should be kept as the second key in the list so that it can continue to
decrypt old data using the previous key(s).

Move the new key ( the key with the highest version ) to the top of the list so that all 
new data is encrypted with this key.

    symmetric-encryption --activate-key

Restart the application so that it will encrypt using the new encryption key.

## Step 5: Re-encrypting existing data

For PCI Compliance it is necessary to re-encrypt old data with the new key and
then to destroy the old key so that it cannot be used again.

The sister project [RocketJob](https://rocketjob.reidmorrison.com) comes with a batch job to re-encrypt
all the data in a relational database for you. Uses multiple workers concurrently to spread the load, 
and is capable of re-encrypting terabytes of data. With built-in throttling mechanisms to allow
re-encryption to continue while live traffic is being processed.

To kick off the re-encryption job, run this from the console or via a migration:

~~~ruby
RocketJob::Jobs::ReEncrypt::RelationalJob.start
~~~
    
A job is created for every database table that contains a column starting with `encrypted_`.
The job is throttled in 2 ways:
* Only one job instance is permitted to run at a time.
* For each job at most 100 workers will work on that table at a time.

Both of the above throttle are configurable and can be tuned for your environment,
by modifying the values below:

~~~ruby
RocketJob::Jobs::ReEncrypt::RelationalJob.throttle_running_jobs   = 1
RocketJob::Jobs::ReEncrypt::RelationalJob.throttle_running_slices = 100
~~~

Custom throttles can be added to the jobs, for example to throttle based on database slave delay, etc.

## Step 6: Re-encrypting Files

Remember to re-encrypt any files on disk that were encrypted with Symmetric Encryption
if they need to be kept after the old encryption key has been destroyed.

For example, with Symmetric Encryption v4, re-encrypt files:

    symmetric-encryption --re-encrypt "/export/**/*"
    
Replace `"/export/**/*"` above as needed to point to where the encrypted files are that
should be re-encrypted using the new key.
    
## Step 7: Remove old key from configuration file

Once all data and files have been re-encrypted using the new key, remove the
old key from the configuration file. 

    symmetric-encryption --cleanup-keys

If you get cipher errors, you can restore the old key in the configuration file and 
then re-encrypt that data too.

## Step 8: Destroying old key

Once sufficient time has passed and you are 100% certain that there is no data
around that is still encrypted with the old key, wipe the old key from all the production
servers.
## Using more than one key at a time

The same versioning that makes rotation work also makes it possible to encrypt different data with
different keys at the same time. There are two quite different things people want here, and they
have different answers.


### Different keys for different data

Give each key its own version in the configuration file, and name the version when encrypting:

~~~ruby
encrypted = SymmetricEncryption.encrypt("Hello World", version: 3)

SymmetricEncryption.decrypt(encrypted)
# => "Hello World"
~~~

Decryption needs nothing extra. The version is in the header, so the right cipher is chosen
automatically.

Files and streams take the same option:

~~~ruby
SymmetricEncryption::Writer.open("archive.enc", version: 3) { |file| file.write(data) }
~~~

Active Record attributes and Mongoid fields take it when they are declared:

~~~ruby
class Person < ActiveRecord::Base
  attribute :ssn,     :encrypted
  attribute :api_key, :encrypted, version: 3
end

class Person
  include Mongoid::Document

  field :encrypted_ssn,     type: String, encrypted: true
  field :encrypted_api_key, type: String, encrypted: {version: 3}
end
~~~

Changing the version of an attribute leaves values that were already written readable, since each
value records the version it was encrypted with. New values are written with the new key, so the
data moves over as records are saved.

Two things to know before relying on this:

* The command line interface treats every version as a rotation of the same key.
  `--activate-key` moves the highest version to the top, and `--cleanup-keys` removes everything
  except the highest. `--cleanup-keys` names the versions it is about to remove and asks first,
  but `--activate-key` will still reorder a configuration file that holds keys for more than one
  purpose, which changes which key new data is encrypted with.
* All of the ciphers have to use a compatible `encoding`, since a value is decoded before its
  header is read. `:base64` and `:base64strict` work together, and mixing anything else is
  refused when the configuration file is loaded.

**If this is a Rails application, and the data is nothing but Active Record attributes, use
[Active Record encryption](migrating.html) instead.** `encrypts :ssn, key: "..."` does the
same job, without a version number to allocate and without the two warnings above.

### A key per customer

The version is a single byte, so a configuration file holds at most 256 ciphers. That is plenty
for rotating a key, and nowhere near enough for a key per customer.

Keys held somewhere else, usually a database table and each encrypted with the global cipher,
are used with `with_cipher`:

~~~ruby
class Customer < ActiveRecord::Base
  attribute :encryption_key, :encrypted

  def cipher
    @cipher ||= SymmetricEncryption::Cipher.new(
      key:         encryption_key,
      cipher_name: "aes-256-gcm",
      version:     1
    )
  end
end

SymmetricEncryption.with_cipher(customer.cipher) do
  person.update!(ssn: "123-45-6789")
end
~~~

Everything encrypted or decrypted inside the block uses that customer's key: Active Record
attributes, Mongoid fields, files and streams alike. Data encrypted with the configured ciphers
is still readable inside the block, so a customer key does not cut the application off from
everything else it encrypted.

In a Rails application the natural place for it is around the request:

~~~ruby
class ApplicationController < ActionController::Base
  around_action :with_customer_encryption_key

  def with_customer_encryption_key(&block)
    return yield if current_customer.nil?

    SymmetricEncryption.with_cipher(current_customer.cipher, &block)
  end
end
~~~

Because the key is chosen by what is in scope rather than by what is in the data, versions no
longer have to be unique across customers. Two customers can both use version 1.

#### Use an authenticated cipher

That is also the risk. Decrypting one customer's data while another customer's cipher is in
scope decrypts it with the wrong key, and nothing in the value says which customer it belonged
to.

With `aes-256-gcm` that fails, loudly:

~~~ruby
SymmetricEncryption.with_cipher(other_customer.cipher) do
  SymmetricEncryption.decrypt(value)
end
# OpenSSL::Cipher::CipherError
~~~

With `aes-256-cbc` it cannot be detected. Decryption occasionally succeeds with the wrong key and
returns whatever that key produces. Use an authenticated cipher for anything encrypted this way.
See [Security](security.html).

#### Rotating a customer's key

Supply the previous key so that data encrypted with it is still readable while new data is
encrypted with the new one:

~~~ruby
SymmetricEncryption.with_cipher(customer.cipher, secondary_ciphers: [customer.previous_cipher]) do
  Person.where(customer_id: customer.id).find_each { |person| person.update_column(:ssn, person.ssn) }
end
~~~

Once nothing is left holding the old key, drop it from the call.

#### Where the scope reaches

The scope belongs to the current fiber. Threads and fibers started inside the block inherit it,
which includes Enumerators, and what they do with it does not leak back out.

A thread that already existed does not inherit it, because the scope is copied when a thread is
created. Handing work to a thread pool, or to a background job, runs that work without the
scope. Set it again there:

~~~ruby
class PersonJob < ApplicationJob
  def perform(customer_id, person_id)
    customer = Customer.find(customer_id)
    SymmetricEncryption.with_cipher(customer.cipher) do
      # ...
    end
  end
end
~~~

## Next steps

* [Command Line](cli.html): every option of the `symmetric-encryption` command.
* [Configuration](configuration.html): the configuration file and the keystores.
* [Security](security.html): authenticated encryption, which matters when using more than one key.
