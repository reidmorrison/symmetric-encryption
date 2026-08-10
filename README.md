# Symmetric Encryption
[![Gem Version](https://img.shields.io/gem/v/symmetric-encryption.svg)](https://rubygems.org/gems/symmetric-encryption) [![Build Status](https://github.com/reidmorrison/symmetric-encryption/workflows/build/badge.svg)](https://github.com/reidmorrison/symmetric-encryption/actions?query=workflow%3Abuild) [![Downloads](https://img.shields.io/gem/dt/symmetric-encryption.svg)](https://rubygems.org/gems/symmetric-encryption) [![License](https://img.shields.io/badge/license-Apache%202.0-brightgreen.svg)](http://opensource.org/licenses/Apache-2.0) ![](https://img.shields.io/badge/status-Production%20Ready-blue.svg)

Encrypt data at rest in Ruby and Rails, with keys held outside your source code.

* Active Record attributes and Mongoid fields.
* Passwords in `database.yml` and other configuration files.
* Entire files and streams, of any size, without loading them into memory.
* Keys in a keystore: a file, an environment variable, AWS KMS, or Google Cloud KMS.
* Key rotation without downtime, since every encrypted value records which key encrypted it.

**Documentation: [encryption.reidmorrison.com](https://encryption.reidmorrison.com/)**

## Do you need it?

Rails 7 added [Active Record encryption](https://guides.rubyonrails.org/active_record_encryption.html).
**If everything you need to encrypt is an Active Record attribute, use that instead.** It is built
in, and it is maintained by the Rails team.

This gem covers what it does not: Mongoid fields, whole files and streams, standalone Ruby,
passwords decrypted before Rails has finished booting, keys held in a cloud KMS, and rotating the key
of a value that has to stay queryable. See
[Do you need it?](https://encryption.reidmorrison.com/#do-you-need-it) for the full comparison.

## Quick start

~~~ruby
gem "symmetric-encryption"
~~~

Generate a configuration file and a key for every environment:

~~~
symmetric-encryption --generate --app-name my_app
~~~

Encrypt an Active Record attribute. The column is a `string`, since the encrypted value is text:

~~~ruby
class Person < ActiveRecord::Base
  attribute :ssn, :encrypted
end

person = Person.create!(name: "Jack", ssn: "123456789")
person.ssn
# => "123456789"
~~~

Continue with the [Guide](https://encryption.reidmorrison.com/guide.html), which builds up from
here one step at a time.

## Documentation

* [Guide](https://encryption.reidmorrison.com/guide.html) — the library, one step at a time.
* [Configuration](https://encryption.reidmorrison.com/configuration.html) — the configuration file and every keystore.
* [Rails](https://encryption.reidmorrison.com/rails.html) — encrypted Active Record attributes.
* [Mongoid](https://encryption.reidmorrison.com/mongoid.html) — encrypted Mongoid fields.
* [Files](https://encryption.reidmorrison.com/files.html) — encrypted files and streams.
* [Command Line](https://encryption.reidmorrison.com/cli.html) — the `symmetric-encryption` command.
* [Key Rotation](https://encryption.reidmorrison.com/key_rotation.html) — introducing a new key without downtime.
* [Security](https://encryption.reidmorrison.com/security.html) — authenticated encryption and PCI compliance.
* [Upgrading](https://encryption.reidmorrison.com/upgrading.html) — what changes between major versions.
* [API](https://encryption.reidmorrison.com/api.html) — the method reference.

## Supported versions

Ruby 3.2 or later, and Rails 7.2 or later when used with Rails. Upgrading from an earlier version of
this gem? See [Upgrading](https://encryption.reidmorrison.com/upgrading.html).

## Sister projects

[IOStreams](https://iostreams.reidmorrison.com) is a streaming library that makes compression,
encryption, file format, and storage location transparent to your code. It has direct support for
Symmetric Encryption, so a file name ending in `.enc` is encrypted or decrypted with the
configuration this gem already loaded. Reach for it when encryption is one step in a larger pipeline:

~~~ruby
IOStreams.path("s3://my-bucket/customers.csv.gz.enc").each(:hash) do |record|
  puts record["name"]
end
~~~

See [Files and Streams](https://encryption.reidmorrison.com/files.html#streaming-with-iostreams) for
when to use IOStreams and when `SymmetricEncryption::Writer` and `SymmetricEncryption::Reader` are
enough on their own.

[Rocket Job](https://rocketjob.reidmorrison.com) is Ruby's missing batch system. It fully supports
Symmetric Encryption to encrypt data in flight and at rest while running jobs in the background.

## Author

[Reid Morrison](https://github.com/reidmorrison)

[Contributors](https://github.com/reidmorrison/symmetric-encryption/graphs/contributors)

## Versioning

This project uses [Semantic Versioning](http://semver.org/).

## Disclaimer

Although this library has assisted in meeting PCI Compliance and has passed previous PCI audits, it
in no way guarantees that PCI Compliance will be achieved by anyone using this library.
