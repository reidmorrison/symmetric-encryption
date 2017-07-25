---
layout: default
---

## Encryption Key Rotation

According to the PCI Compliance documentation: "Cryptographic keys must be changed on an annual basis."

During the transition period of moving from one encryption key to another symmetric-encryption supports multiple 
Symmetric Encryption keys. Since every encrypted value has a header that contains the version number of the key
that was used to encrypt it, that key will be used to decrypt it, even though a new key is already active and
is being used to encrypt new values.

The active key is the first key in the list in `symmetric-encryption.yml`. Other keys are only used to decrypt
values that were encrypted with those keys.

Encryption keys are secured (encrypted) using a Key Encryption Key (RSA Private key). New keys are secured using the
same Key Encryption Key, so that multiple encryption keys can be secured at the same time.


### Recommended steps

Below are the recommended steps to perform "hot" key rotation, so that the encryption key can be changed without
requiring system downtime or maintenance window.

The steps can be reduced if they are being performed during a maintenance window. In this case do not supply
the `--deploy` option below so that new key will be active immediately, and skip step 4 below.

### 1. Add the new key as secondary key

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
    
Copy the key file to every server in that particular environment that runs the application or uses Symmetric Encryption.

If the keys for multiple environments are generated above, then move the relevant key files to the servers for that environment.

By default the key files are located in `/etc/symmetric-encryption`.

    
### 2. Re-encrypt all passwords in the source repository

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
    
### 3. Deploy

Deploy the updated source code to each environment so that the new key is available to all
servers for decryption purposes.

### 4. Activate the new key

Once the new key has been deployed as a secondary key, the next deploy can move
the new key to the top of the list so that it will be the active key for encrypting new data.
The previous key should be kept as the second key in the list so that it can continue to
decrypt old data using the previous key(s).

Move the new key ( the key with the highest version ) to the top of the list so that all 
new data is encrypted with this key.

    symmetric-encryption --activate-key

Restart the application so that it will encrypt using the new encryption key.

### 5. Re-encrypting existing data

For PCI Compliance it is necessary to re-encrypt old data with the new key and
then to destroy the old key so that it cannot be used again.

The sister project [RocketJob](http://rocketjob.io) comes with a batch job to re-encrypt
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

Note: This job is included in the Rocket Job Pro version.

### 6. Re-encrypting Files

Remember to re-encrypt any files on disk that were encrypted with Symmetric Encryption
if they need to be kept after the old encryption key has been destroyed.

For example, with Symmetric Encryption v4, re-encrypt files:

    symmetric-encryption --re-encrypt "/export/**/*"
    
Replace `"/export/**/*"` above as needed to point to where the encrypted files are that
should be re-encrypted using the new key.
    
### 7. Remove old key from configuration file

Once all data and files have been re-encrypted using the new key, remove the
old key from the configuration file. 

    symmetric-encryption --cleanup-keys

If you get cipher errors, you can restore the old key in the configuration file and 
then re-encrypt that data too.

### 8. Destroying old key

Once sufficient time has passed and you are 100% certain that there is no data
around that is still encrypted with the old key, wipe the old key from all the production
servers.

### Next => [PCI Compliance](pci_compliance.html)
