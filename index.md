---
layout: default
---

Any project that wants to meet PCI compliance has to ensure that the data is encrypted
whilst in flight and at rest. Amongst many other requirements all passwords
in configuration files have to be encrypted.

This Gem helps achieve compliance by supporting encryption of data in a simple
and consistent way for Ruby and Ruby on Rails projects.

Symmetric Encryption uses OpenSSL to encrypt and decrypt data, and can therefore
expose all the encryption algorithms supported by OpenSSL.

## Examples

### Encryption Example

```ruby
SymmetricEncryption.encrypt "Sensitive data"
```

### Decryption Example

```ruby
SymmetricEncryption.decrypt "JqLJOi6dNjWI9kX9lSL1XQ=="
```

## Dependencies

- Ruby 1.9.3 (or above) Or, JRuby 1.7.3 (or above)
- Optional: To log to MongoDB, Mongo Ruby Driver 1.5.2 or above

### Installation

Add the following line to Gemfile

```ruby
gem 'symmetric-encryption'
```

Install the Gem with bundler

    bundle install

### Support

To report any issues, or submit any questions: [Github Issues](http://github.com/reidmorrison/symmetric-encryption/issues)

### Disclaimer

Although this library has assisted in meeting PCI Compliance and has passed
previous PCI audits, it in no way guarantees that PCI Compliance will be
achieved by anyone using this library.
