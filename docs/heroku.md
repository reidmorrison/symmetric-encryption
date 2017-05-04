---
layout: default
---

## Configuring Symmetric Encryption for Heroku


### Add to Gemfile

Add the following line to your Gemfile _after_ the rails gems:

~~~ruby
gem 'symmetric-encryption'
~~~

Install using bundler:

    bundle

### Generate configuration file

Deploying to Heroku requires the encrypted key to be stored in an environment
variable rather than as a file on disk.

Generate the configuration file:

    rails g symmetric_encryption:heroku_config

The output would be similar to the following, except your keys will be different:

~~~
Symmetric Encryption config not found.
To generate one for the first time: rails generate symmetric_encryption:config

      create  config/symmetric-encryption.yml


********************************************************************************
Add the release environment key to Heroku: (Optional)

  heroku config:add RELEASE_KEY1=NmWJ6QF7tpVphtkVAWo0dloPQdhSkQ/GNR+TTScM4UKqzLGH/6I9Gc2eT3Odau6vRwJwR8G9G1wwrrIxmIKA4SD9+WF8r8gZTFqc8SR61gkCzbpKOG2MrPFZN84Y96A9C+qPU7tGHRQwhbnPyjkjdZVVIrp8oW1DipzmxeRV5KYAJu9hoGkkd6vMmV9hVTjyAlTzgqtv1I/9olaNDPtiPLNddfG8xB2rP5pmzqkRZUZ1ihe5b9ecb+1q0N0OVV3V9NbftqKG+yb8DbPkGkA2Mraj464PA6LLYkJv7+ffLvZAf4zlv0BPaXLbx31/Zwb07j+Qx/e+m43UvdSWFHUghQ==

Add the production key to Heroku:

  heroku config:add PRODUCTION_KEY1=dnqpGTng7QNOXOkGqqUAmSdQbL8Dp8nf2qa3JoUbeYpNTELKX1o/HeSNADL4Btr7dLrdonUJvwqRp1B9EtVFRaNJBqkrKC4/0FI+km6LrAa36QGwqHXZ6XBMGoqSJ4smgIF1YgxTeZfRGMDwJ+szq7RuNSNdRd+jHQvJ8TEQYte/3oFoYkHxQVCdOIdmdhPebiqk6snRRvbilitGEnAbUTHQGzkpf8cEdCv8qfecIQoJDvDSWUzEMJ+gMm80W26xBxlfd72Raog61R5Vu5l/bv5X7+pHvtRio9xr+/HS2y+YNFNH52oUOu2dMcBcV7AFsIgSY06xtBF9fO53WcIVqA==

********************************************************************************
~~~

#### Notes

* Ignore the warning about `Symmetric Encryption config not found` since it is
being generated.
* The encrypted keys for the release and production environments are displayed on
screen and must be entered manually as environment variables into Heroku so that the
application can find them when it starts.

Follow the onscreen instructions to add the environment keys to Heroku.
The release environment is optional.

### Save to version control

The generated configuration file should be checked into the source code control system.
It does Not include the Symmetric Encryption keys.

## Supporting multiple production encryption keys

To create multiple encryption keys in production where each heroku application has its own encryption key, this can be done as follows:

Generate the configuration file which includes the RSA key to unlock the encryption key, as well as the first encryption key:

~~~
$ rails g symmetric_encryption:heroku_config

Symmetric Encryption config not found.
To generate one for the first time: rails generate symmetric_encryption:config

      create  config/symmetric-encryption.yml


********************************************************************************
Add the release environment key to Heroku: (Optional)

  heroku config:add RELEASE_KEY1=a9NwhS6Wv/Kd2ltGkO9/5mqT6yPA5YcnRWicAYU8d7Lc71sIxWq41wyL8h/jLKMUZfe2wUU/4lv0PfTJ8E6Or+5zNaFLWwuygzZgWFB2a0lyIVetV7pLgSq1ndFCzgbOoPzTSk9HL5FsJEXJgvFckPp+OP1+QUfRuYXyZ8YzMvgq33sBWNciB4W583BuOvBwvx2OT9apmIyWE9NU3+3axHq89NJs3Yo2Yg7tNVxsCBlkxhtOq6glmpoTHIxv3HPmGbG0o1rD6K94DkcWs9iV8UhxTn2l2bh/ejaNWmgJRLcECo+/y1KkChe5xiUI+TptEnNPWvDbosanAQFj94RkLg==

Add the production key to Heroku:

  heroku config:add PRODUCTION_KEY1=nqNxlfsq/XX4ffoF2Z7APAe2778pKVrJsxEG63PwnU+f6IUUwhj1S1v8iHgSIAibqW85EDWT3m1RCUPw7tAXyr3J4HpfgyTheJTIIV3RQDXC09l0Mk9n1xS77tS4xIBX+YRRuA0PYF/bHMezi69Khie6o+VL0/GKpo/Pkhrhwb/Hel90A2f+stuhrl/aXWHnM9vsKFG6Ufrusg1ZQejuoburzmQqYVorI/BVvufTxNq72stRWdKruTZlgKTEP5LMSxps28jnh4X4bZXU2StbTkOFJzGEBhDWhpepXrUgXZ+3MHHaTg45ZSj+LUFil1pBPgZKaBDDad1ATTfaXwNLJg==

********************************************************************************

~~~

Then generate new additional keys for the other heroku applications:

~~~
$ rails generate symmetric_encryption:new_keys production

Generated new Symmetric Key for encryption. Set the KEY environment variable in production to:
IVFlzQP604dlD98Tj94gJzAqqmD2ZFGlScbqiUCJgMYZrfhDymxm+LO2TtIP
+tSq4fnXfuNbMlCkTCmyNUkXlJU9VC2oGIvt4aW/wZgaNac8jsjfZQa59w3d
IaNuzvy9DAEskFQhmbHSCIemgAIvsyKjJ46CKOO9c8UifIlA/fSe89HhlwHJ
e2rJj4K8hOCKonxvnIY2DbJLa78+THVN25AQMjRq3ISZjlULxYn9chpGTuTB
KKQ8w9mdnqwpkr6wQVL5zCQLv6yIdVZrp/EHWoBk5tfChWUmB97mY5I3vogk
JbwCtvOPpumiaeORimo+cDHoRGFDK1ACVeWg1hRkvQ==
~~~

The above output needs to be reformatted to remove the newlines and to include the appropriate heroku command.
For example the above output would be added as follows:

~~~
  heroku config:add PRODUCTION_KEY1=IVFlzQP604dlD98Tj94gJzAqqmD2ZFGlScbqiUCJgMYZrfhDymxm+LO2TtIP+tSq4fnXfuNbMlCkTCmyNUkXlJU9VC2oGIvt4aW/wZgaNac8jsjfZQa59w3dIaNuzvy9DAEskFQhmbHSCIemgAIvsyKjJ46CKOO9c8UifIlA/fSe89HhlwHJe2rJj4K8hOCKonxvnIY2DbJLa78+THVN25AQMjRq3ISZjlULxYn9chpGTuTBKKQ8w9mdnqwpkr6wQVL5zCQLv6yIdVZrp/EHWoBk5tfChWUmB97mY5I3vogkJbwCtvOPpumiaeORimo+cDHoRGFDK1ACVeWg1hRkvQ==
~~~

The above step can be run as many times as need to generate new encrypted symmetric keys. Old ones can be discarded if not used.

### Securing the Symmetric Encryption production keys

The production encryption keys added to your Heroku configuration are only as secure as your
Heroku account and password are.

#### Note

* Heroku administrators that have access to your Heroku environment variables will have full
  access to your encryption keys, and can therefore decrypt your encrypted data.

### Next => [Standalone Configuration](standalone.html)
