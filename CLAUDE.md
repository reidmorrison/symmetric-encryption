# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`symmetric-encryption` is a Ruby gem (currently v5.0.0, in development on branch `feature/housekeeping`) that encrypts ActiveRecord attributes, Mongoid fields, passwords in config files, and whole files/streams using OpenSSL. Minimum Ruby 3.2, minimum Rails/ActiveRecord 7.2.

Public docs live in [docs/](docs/) and are published to https://encryption.reidmorrison.com/ via GitHub Pages (Jekyll front-matter in each file). Update these when changing user-facing behavior.

## Commands

```bash
bundle exec rake test                      # Run the suite against the default Gemfile
bundle exec rake test TEST=test/cipher_test.rb
bundle exec ruby test/cipher_test.rb -n "/permit replacing value/"   # Single test by name

appraisal install                          # Regenerate gemfiles/*.gemfile and install
bundle exec rake                           # Default task: runs the suite for every appraisal
appraisal rails_8.1 rake test              # One Rails version (rails_7.2, rails_8.0, rails_8.1)

bundle exec rubocop
bundle exec rubocop -a
```

Note: bare `rake` triggers `appraisal` unless `APPRAISAL_INITIALIZED` or `TRAVIS` is set, so use `rake test` for a quick single-version run.

Tests are Minitest with the spec DSL (`describe`/`it`). [test/test_helper.rb](test/test_helper.rb) loads [test/config/symmetric-encryption.yml](test/config/symmetric-encryption.yml) with env `test` and chmods the test key files to 0600 (git does not preserve the mode, and `Keystore::File#read` refuses to read a key file with looser permissions).

Several test files silently do nothing, so a green run exercises far less than the file count suggests:

- AWS/GCP keystore tests skip without real credentials.
- [test/mongoid_test.rb](test/mongoid_test.rb) wraps everything in `begin ... rescue LoadError` and requires a stale path (`symmetric_encryption/extensions/mongoid/encrypted`, actually at [railties/mongoid_encrypted.rb](lib/symmetric_encryption/railties/mongoid_encrypted.rb)), so it always prints the "mongoid gem is not installed" message and skips even when mongoid is present.
- [test/active_record_test.rb](test/active_record_test.rb) is entirely wrapped in `if ActiveRecord.version <= 7.0.0`. It covers the legacy `attr_encrypted` path, which Rails 7+ cannot use, so it never runs on any supported version.

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs Rails 7.2/Ruby 3.2, Rails 8.0/Ruby 3.4, Rails 8.1/Ruby 4.0 with a mongo service, via `BUNDLE_GEMFILE=gemfiles/rails_X.Y.gemfile bundle exec rake test`.

## Architecture

### Entry points

[lib/symmetric_encryption.rb](lib/symmetric_encryption.rb) (and its alias [lib/symmetric-encryption.rb](lib/symmetric-encryption.rb)) is the full entry point: it loads core, then optionally hooks Rails via the Railtie and ActiveRecord/Mongoid via `ActiveSupport.on_load`, so gem load order does not matter. [lib/symmetric_encryption/core.rb](lib/symmetric_encryption/core.rb) is the framework-free entry point for standalone Ruby apps and declares nearly everything else as `autoload`; add new files there. One of those autoloads, `EncryptedStringType`, points at a file that does not exist and nothing references it.

### The layered model

Understanding these five layers explains most of the codebase:

1. **`SymmetricEncryption` module** ([symmetric_encryption.rb](lib/symmetric_encryption/symmetric_encryption.rb)) is the global API and holds module-level state: `@cipher` (primary), `@secondary_ciphers`, `@randomize_iv`, `@select_cipher`. `encrypt`/`decrypt` coerce non-string types through `Coerce` and delegate to a Cipher.
2. **`Config`** ([config.rb](lib/symmetric_encryption/config.rb)) reads `symmetric-encryption.yml` (ERB-evaluated), migrates legacy formats, and sets the primary + secondary ciphers. The file is read *and written* by the CLI, so `write_file` and `deep_stringify_keys` must round-trip cleanly.
3. **`Cipher`** ([cipher.rb](lib/symmetric_encryption/cipher.rb)) pairs a `Key` with a `version`, an `Encoder`, and the `always_add_header` flag. `encrypt` = binary_encrypt + encode; `decrypt` = decode + binary_decrypt.
4. **`Key`** ([key.rb](lib/symmetric_encryption/key.rb)) is the thin OpenSSL wrapper (key + iv + cipher_name). A Key can itself be a *key encrypting key* that decrypts another key, and `Keystore.read_key` recurses through nested `key_encrypting_key` hashes to arbitrary depth.
5. **`Keystore`** ([keystore.rb](lib/symmetric_encryption/keystore.rb)) resolves where the data encryption key lives: `File`, `Environment`, `Heroku`, `Memory` (encrypted key inline in the config), `Aws` (KMS), `Gcp` (Cloud KMS). Each implements `.generate_data_key`, `#read`, `#write`. `Keystore.keystore_for` infers the class from config keys when `:keystore` is absent.

### Versioned ciphers and the binary header

Every cipher has an integer `version`. Encrypted values normally carry a binary header (`@EnC` magic + version byte + flag byte + optional iv/key/cipher_name/auth_tag length-prefixed fields) parsed by [header.rb](lib/symmetric_encryption/header.rb). This is what makes key rotation work: `decrypt` reads the version from the header and looks up the matching cipher among primary + secondary ciphers.

Deliberate design constraint, do not "fix" it: `decrypt` never falls back to trying other ciphers when one fails, because decrypting with the wrong key can silently succeed and return garbage. When there is no header, cipher choice comes from an explicit `version:` argument or a user-supplied `SymmetricEncryption.select_cipher` block.

Changing the header format or the flag bits breaks every value already encrypted in the field. The header is also the on-disk format for `Writer`/`Reader`.

### Framework integration

- **ActiveRecord (current)**: [active_record/encrypted_attribute.rb](lib/symmetric_encryption/active_record/encrypted_attribute.rb) is an `ActiveModel::Type::String` subclass registered as the `:encrypted` type, used via `attribute :ssn, :encrypted`.
- **ActiveRecord (legacy)**: `attr_encrypted` ([active_record/attr_encrypted.rb](lib/symmetric_encryption/active_record/attr_encrypted.rb)) generates accessors through [generator.rb](lib/symmetric_encryption/generator.rb). It is only included for ActiveRecord <= 7.0 because Rails 7 defines its own `encrypted_attributes`.
- **Mongoid**: [railties/mongoid_encrypted.rb](lib/symmetric_encryption/railties/mongoid_encrypted.rb) adds the `encrypted: true` field option.
- **Railtie**: [railtie.rb](lib/symmetric_encryption/railtie.rb) loads config in `before_configuration`, deliberately earlier than ActiveRecord, because `database.yml` may itself contain encrypted passwords. Honors `SYMMETRIC_ENCRYPTION_CONFIG` and `SYMMETRIC_ENCRYPTION_ENV`.

### Files and streams

`Writer`/`Reader` ([writer.rb](lib/symmetric_encryption/writer.rb), [reader.rb](lib/symmetric_encryption/reader.rb)) are IO-like wrappers that generate a random key and iv per file and store them (key encrypted with the global cipher) in the file header, with optional zlib compression. `Reader` supports buffered `read`/`gets`/`each_line`/`seek`.

### CLI

`bin/symmetric-encryption` runs [cli.rb](lib/symmetric_encryption/cli.rb): generate config and keys, rotate data keys (`--rotate-keys`, with `--rolling-deploy` inserting the new key second so it is readable before it is active), rotate key encrypting keys (`--rotate-kek`), activate/cleanup keys, encrypt/decrypt files and strings, re-encrypt files. It rewrites `symmetric-encryption.yml` in place, so config round-tripping matters.

## Conventions

- Rubocop enforced, `double_quotes`, trailing dot position, table-aligned hashes, 128 char lines (relaxed in tests). Metrics limits are deliberately softened in [.rubocop.yml](.rubocop.yml).
- Aligned assignment and `# @formatter:off`/`on` blocks around autoload and field lists are intentional; leave the alignment as-is.
- Keyword arguments for anything optional. This was the defining API change of v4 and is the house style.
- Backward compatibility with data encrypted by older versions is a hard requirement. Legacy config shapes (`private_rsa_key`, `encrypted_iv`, `iv_filename`) are migrated in `Keystore.migrate_config!` and `Config.migrate_old_formats!` rather than dropped.
