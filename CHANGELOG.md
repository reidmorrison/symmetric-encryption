# Change Log

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [5.0.0] Unreleased

### Breaking changes

- Ruby 3.2 is now the minimum supported runtime. Earlier versions are end-of-life and are no
  longer tested.
- Rails 7.2 is now the minimum supported version of Rails / Active Record.
- `attr_encrypted` has been removed. It was already unusable under Rails 7, which defines its
  own conflicting `encrypted_attributes` method, so it was only included for Active Record 7.0
  and earlier. Declare encrypted attributes with the `:encrypted` attribute type instead:

  ~~~ruby
  # Before
  class Person < ActiveRecord::Base
    attr_encrypted :name, random_iv: false
    attr_encrypted :age, random_iv: true, type: :integer
  end

  # After
  class Person < ActiveRecord::Base
    attribute :name, :encrypted, random_iv: false
    attribute :age, :encrypted, type: :integer
  end
  ~~~

  Data encrypted by `attr_encrypted` is still readable, the encrypted value format is unchanged.
  Note that `attr_encrypted` required the database column to be named `encrypted_name`, whereas
  the attribute type uses a column with the same name as the attribute. See the
  [Frameworks Guide](https://encryption.reidmorrison.com/frameworks.html) for migration details.

  Removed along with it: `encrypted_attributes`, `encrypted_keys`, `encrypted_columns`,
  `encrypted_attribute?` and `encrypted_column?`.
- The Google Cloud KMS keystore now requires `google-cloud-kms` v2. See below.
- Encrypted attributes are cast when they are assigned, not only when they are read back from the
  database. Issue #146: with `attribute :age, :encrypted, type: :integer`, `person.age = "124"` left
  the string `"124"` in place until the record had been saved and reloaded, when it turned into
  `124`. The declared type is now applied immediately, using Active Record's own casting rules, so
  an encrypted attribute behaves like the equivalent unencrypted one:

  ~~~ruby
  person.age = "124"
  person.age
  # Before: "124"
  # After:  124
  ~~~

  Two consequences worth checking before upgrading:

  * A blank string becomes `nil` for every type other than `:string`, so the column now holds `NULL`
    rather than an encrypted `""`.
  * A value that cannot be cast no longer raises `Coercible::UnsupportedCoercion`. It becomes
    whatever Active Record would use: `0` for `:integer` (and `"12abc"` becomes `12`), `0.0` for
    `:float` and `:decimal`, `nil` for `:date`, `:datetime` and `:time`, and `true` for `:boolean`.
    Add `validates :age, numericality: true` to reject it, exactly as for an unencrypted attribute.
    The value that was assigned is still available in `age_before_type_cast`, which is what that
    validation reports on.

  `:date`, `:datetime` and `:time` are still cast by the coercible gem rather than by Active Record,
  because `ActiveModel::Type::Time` is meant for time columns and discards the date portion of the
  value, and `ActiveModel::Type::DateTime` returns a `Time` where reading the attribute back returns
  a `DateTime`. `:json` and `:yaml` values are left as they were assigned, which is what Active
  Record's own `:json` type does.

  A `type:` that is not one of the supported types is now rejected with an `ArgumentError` naming
  the valid ones when the attribute is declared, rather than failing later with a coercion error.
  Mongoid fields have always been checked this way.

- Encrypted Active Record attributes are no longer written to the log in the clear. Issue #128: an
  encrypted attribute returns its decrypted value, so `Rails.logger.info(person)`, `inspect` and
  `attribute_for_inspect` all wrote out the value the attribute exists to protect. Attributes
  declared with the `:encrypted` type are now added to the model's `filter_attributes` as they are
  declared, and to the Rails application's `config.filter_parameters`, which is what Active Record's
  own `encrypts` does:

  ~~~ruby
  Rails.logger.info(person)
  # Before: #<Person id: 1, name: "Jack", ssn: "top_secret">
  # After:  #<Person id: 1, name: "Jack", ssn: [FILTERED]>
  ~~~

  Listed as a breaking change because it applies to every model that already declares an encrypted
  attribute, without anything being added to it. Anything that reads a decrypted value back out of
  `inspect`, `attribute_for_inspect` or the logs, including tests that assert on them, sees
  `[FILTERED]` instead. Reading the attribute itself is unchanged, as is `attributes`, and `as_json`
  keeps rendering the decrypted value unless the model opts out of it, see below.

  Set `config.symmetric_encryption.filter_encrypted_attributes = false` before the models are loaded
  to restore the previous behavior and leave the filtering to the application.

  Adding to a model's `filter_attributes` copies the list it inherits from `ActiveRecord::Base`,
  which is where Rails puts the application's `config.filter_parameters`. A model that is loaded
  before Rails has set those, from a gem's railtie or from an initializer that references the model,
  therefore filters its encrypted attributes but not the attributes named in
  `config.filter_parameters`. Active Record's own encryption copies the list at declaration time in
  exactly the same way. See the
  [Frameworks Guide](https://encryption.reidmorrison.com/frameworks.html) for what to do in a model
  that is loaded that early.

### Added

- `SymmetricEncryption::ActiveRecord::ExcludeFromJson` keeps encrypted attributes out of the JSON
  representation of a model, so that they cannot be leaked by `render json: @person`. Also issue
  #128:

  ~~~ruby
  class Person < ActiveRecord::Base
    include SymmetricEncryption::ActiveRecord::ExcludeFromJson

    attribute :ssn, :encrypted
  end

  Person.create(name: "Jack", ssn: "top_secret").as_json
  # Before: {"id" => 1, "name" => "Jack", "ssn" => "top_secret"}
  # After:  {"id" => 1, "name" => "Jack"}
  ~~~

  It has to be included in the model, rather than being applied to every encrypted attribute the way
  the log filtering is, because an encrypted attribute that is deliberately part of an API response
  has to keep working, and because Active Record's own `encrypts` renders decrypted values into JSON
  as well. Once included, `as_json(only: %i[ssn])` does not bring the attribute back either.
  Rendering it takes asking for it by name, with `as_json(methods: :ssn)`. See the
  [Frameworks Guide](https://encryption.reidmorrison.com/frameworks.html).

- The keystores that hold their keys in files now accept the permissions, owner and group those key
  files are allowed to have, so that Symmetric Encryption can be run where something other than the
  application decides them.
  A Kubernetes secret volume mounted with `readOnly: true` mounts its files as `0644` owned by
  `root`, whatever user the container runs as, which the previous fixed expectation of `0600` or
  `0400` owned by the current user rejected outright, leaving no way to start the application:

  ~~~yaml
  production:
    ciphers:
      - key_filename: /etc/keys/my_app_production_v1.encrypted_key
        permissions: "0644"
        owner: root
        group: root
  ~~~

  Supply them per key file, or as a list when more than one value is acceptable. Permissions are an
  octal file mode, and new key files are created with the first one. Owner and group are a name or a
  numeric id. Key files are still verified, against what the configuration says rather than against
  the default, and the defaults are unchanged when nothing is supplied: `owner` replaces the check
  that the key file is owned by the user running the application, and `group` adds a check that was
  not performed at all before. This applies to the file keystore, and to the AWS KMS and Google
  Cloud KMS keystores, which also hold their encrypted data encryption key in a local file. See the
  [Configuration Guide](https://encryption.reidmorrison.com/configuration.html#key-file-permissions-and-ownership).

- `symmetric-encryption --generate --key-permissions 0644` writes the above configuration and
  creates the key files with those permissions. `--rotate-keys` and `--rotate-kek` carry all three
  settings into the entries they write, so they only have to be supplied once. There is no
  equivalent option for `owner` and `group`, since `symmetric-encryption` cannot give a file away to
  another user.

  The error message raised for a key file with the wrong permissions now reports the mode alone,
  `0644`, instead of the mode with its file type bits, `100644`. The wrong owner or group is now
  reported as two separate messages, each naming what it found and what it expected.

  `SymmetricEncryption::Keystore::File::ALLOWED_PERMISSIONS` has been replaced by
  `SymmetricEncryption::Utils::FileAccess::DEFAULT_PERMISSIONS`, which holds file modes as Integers
  rather than strings that included the file type bits. The checks themselves now live in
  `SymmetricEncryption::Utils::FileAccess`, shared by every keystore that reads a key file.

- A [Files and Streams Guide](https://encryption.reidmorrison.com/files.html) documents `Writer`
  and `Reader`, which previously had three examples on the home page and nothing else. It covers
  supplying a stream in place of a file name, which of `read`, `seek`, `size` and the rest each
  reader supports, how the encoding of decrypted data differs between them, who closes what, and
  how to hand an encrypted or decrypted stream to an HTTP client. Issues #93 and #80.

  It also points at the sister project [IOStreams](https://iostreams.reidmorrison.com/), which has
  built in support for Symmetric Encryption and is the better tool whenever encryption is one step
  in a larger pipeline, since it layers compression, file formats and storage locations such as S3
  and SFTP on top of it. Neither fix below changes how IOStreams behaves: it always hands
  `Writer.open` an already open stream rather than a file name, so the compression default it
  reaches is unaffected, and its own streams were already being closed by the layer above.

### Fixed

- `SymmetricEncryption::Reader.open` leaked a file descriptor on every uncompressed file or stream
  it was given, and left the caller's stream open. The block form decides whether to close what it
  built with `respond_to?(:closed?)`, and `Reader#closed?` was defined below `private`, so the
  check was always false and the reader was never closed. Compressed files were unaffected, since
  `.open` hands back a `Zlib::GzipReader` in that case and its `closed?` is public. `Reader.read`
  and `Reader.decrypt` inherited the leak. `Reader#closed?` is now public, which is also what
  callers checking whether a reader is still open would expect. Issue #93.
- `SymmetricEncryption::Writer.open` compressed every file, including targets named `.zip`, `.gz`
  and `.xlsx`, whose contents are compressed already. It has documented since v4.1.0 that
  compression defaults to off for those extensions, but the check ran against the open `File`
  object rather than the file name, because the name had already been replaced by the time the
  test was reached, and a `Regexp` never matches a `File`. Compressing again costs time and
  produces slightly larger output, it never produced an unreadable file, and existing encrypted
  files are unaffected. Writing to one of those extensions now leaves the data uncompressed, as
  documented. Pass `compress: true` to keep the previous behaviour.

  The same check also matched any file name ending in a `.`, and `Writer.encrypt` still documented
  the pre v4.1.0 default of `false`. Both corrected.
- A key or iv of the wrong length is now rejected when the configuration is loaded, instead of by
  OpenSSL on the first encryption. `Cipher` and `Key` both raise an `ArgumentError` that names the
  cipher, the number of bytes it requires, and the number of bytes that were supplied, and points at
  the `!!binary` YAML tag. OpenSSL's own `key must be 32 bytes` named neither the cipher nor where
  the key came from, and arrived long after the configuration that supplied it was read.

  This catches the most common way of getting a key into `symmetric-encryption.yml`. `key` and `iv`
  are raw binary, but binary does not survive a YAML string: a hex encoded key is twice as many bytes
  as it looks, and a `"\xB1"` escape is parsed as a character that is two bytes in UTF-8. Both now
  fail on startup with an explanation rather than silently later. See
  [Supplying the key in the configuration file](https://encryption.reidmorrison.com/configuration.html)
  for how to supply a binary key. Truncating a key to make the error go away changes the key and
  loses access to everything already encrypted with it.
- An encrypted attribute reported itself as changed when a value equal to the one it already held
  was assigned as a string. Assigning `"124"` over `124` gave `age_changed? # => true` and wrote the
  same value back to the database on every save. Casting on assignment, above, removes it.
- Validations that read `*_before_type_cast` reported nothing on an unsaved record. The `:encrypted`
  type answered `changed_in_place?` with `true` for any attribute that had never been read from the
  database, because it compared a decrypted `nil` against the value that was assigned. Active Record
  skips `*_before_type_cast` while an attribute is changed in place, so
  `validates :age, numericality: true` passed silently on `person.age = "abc"`.
- The AWS KMS and Google Cloud KMS keystores never checked the encrypted data encryption key file
  they read. Both hold that key in a local file, exactly as the file keystore does, but their shared
  read path carried a `TODO: Validate that file is not globally readable.` and performed no check at
  all, so a world readable or world writable key file was accepted without complaint. Both now
  verify the file, and both accept `permissions`, `owner` and `group` for environments that decide
  those themselves. The file keystore was unaffected, it has always had its own check.

  The encrypted data encryption key is only useful to an attacker who also has access to KMS, so
  this is a defence in depth gap rather than an immediate key disclosure. It is still worth
  reviewing the permissions on existing key files: this check now fails on startup rather than
  quietly reading them.
- `symmetric-encryption --rotate-kek` raised `ArgumentError` on every supported Ruby.
  `Keystore.rotate_key_encrypting_keys!` passed a Hash positionally to two methods that only
  accept keyword arguments, so rotating key encrypting keys was impossible.
- `--rotate-kek` also wrote an explicit `nil` for `encoding` and `always_add_header` when those
  options were not set in the configuration file, producing a file that could no longer be
  loaded. They are now only written when they were set explicitly.
- Re-encrypting a whole file (`--re-encrypt`) only worked for files in the current directory.
  `ReEncryptFiles#re_encrypt_file` prefixed the entire path when building its temporary file
  name, so a nested path raised `Errno::ENOENT`, which aborted the run for the remaining files.
- `Keystore::Memory#write` assigned to a reader-only attribute and raised `NoMethodError`, which
  also broke `Keystore::Memory.generate_data_key`. The configuration it returns also referenced
  an undefined `iv`.
- `Encoder.encode` and `Encoder.decode` called an undefined method and always raised.
- `SymmetricEncryption.encrypt(value, type: :json)` failed with `NoMethodError` in applications
  that had not already loaded the `json` standard library. `Coerce` now requires it.
- `Writer#write` returned `data.length` after coercing the value with `to_s`, so writing anything
  that is not a String raised `NoMethodError`. It now returns the number of bytes written.
- `SymmetricEncryption.encrypted?` returned `false` for correctly encrypted values after the
  primary cipher was replaced, which every `Config.load!` and `SymmetricEncryption.cipher=` does.
  It compared against a module level copy of the magic header, taken from whichever cipher
  happened to be active on the first call. Since `encrypted?` backs the `symmetric_encryption`
  validator, a rotation performed after boot could make validations reject valid data. It now
  reads the header from the current cipher, which memoizes it per instance.
- `Cipher#encoding=` discarded the encoder derived from the previous encoding but kept the magic
  header, so changing the encoding of a cipher left `encoded_magic_header` reporting the old one.
- `Header.present?`, `Header#parse`, `Cipher#binary_decrypt` and `Key#decrypt` no longer change
  the encoding of the string passed to them. They called `force_encoding` on the argument, which
  modifies the caller's object, so passing a frozen string raised `FrozenError`. Applications
  that enable frozen string literals could not call them at all. Each now works against a binary
  copy, and only when the string is not already binary, so the common path allocates nothing.
  `Header#parse!` still modifies the buffer it is given, which is its documented purpose.
- Loading the gem no longer emits `warning: literal string will be frozen in the future` under
  Ruby 3.4 and later. `Header::MAGIC_HEADER` built its value by mutating a string literal, so the
  warning appeared on require in any application that enables deprecation warnings. Two internal
  buffers, in `Reader#read` and `ReEncryptFiles#re_encrypt_lines`, were also literals that are
  appended to. Reported by @moznion in #172.

### Fixed: AWS KMS keystore

- A KMS call that kept raising `NotFoundException` retried forever, calling `create_master_key`
  on every iteration, which creates a new Customer Master Key in AWS each time. The attempt
  counter was declared inside the block being retried, so `retry` reset it and the limit could
  never be reached.
- `Utils::Aws#delete_master_key` printed its responses with `ap`, which comes from
  `amazing_print`, a development dependency. It raised `NoMethodError` in any application that
  does not happen to load that gem.

### Fixed: Google Cloud KMS keystore

- The keystore referenced `Google::Cloud::Kms::V1::KeyManagementServiceClient`, which was removed
  from `google-cloud-kms` years ago, so every method raised `NameError`. It now uses
  `KeyManagementService::Client` and passes keyword arguments to `encrypt` and `decrypt`.

  The fully qualified crypto key name is unchanged,
  `projects/{project}/locations/{location}/keyRings/{app_name}/cryptoKeys/{environment}`,
  so existing configurations still resolve to the same key.
- `Keystore::Gcp.generate_data_key` did not accept a `dek:` argument, so key rotation raised
  `ArgumentError` for this keystore. It now accepts a supplied data encrypting key and ignores
  arguments meant for other keystores, matching every other keystore.

### Internal

- Line coverage is now 96%, up from 59%. New tests for the previously untested CLI, `Config`,
  `Generator`, `ReEncryptFiles`, `Keystore::Memory`, `Utils::Files`, and the AWS and GCP
  keystores. Every bug listed above was found by writing them.
- The AWS and GCP keystores are now tested without credentials and without network calls. AWS
  uses the SDK's own response stubbing, so request parameters are still validated against the
  real KMS API model. The tests that talk to the real services are unchanged and still skip
  unless credentials are configured.
- The Mongoid tests had been silently skipping for years: they required a path that no longer
  exists, inside a `rescue LoadError`, so every run reported that the mongoid gem was not
  installed even when it was. They now run, and skip with an explanatory message only when
  MongoDB is genuinely unavailable. Added `docker-compose.yml` to run MongoDB locally.
- Added SimpleCov, enabled with `COVERAGE=true`.

## [4.6.0] 2022-11-06

- Fix `attribute_changed?` and `saved_change_to_attribute` under Rails 7.
- Fix migration of ciphers that use `encrypted_iv`.

## [4.5.0] 2022-04-27

- Support Rails 7.0 and Ruby 3.1.

## [4.4.0] 2021-10-07

- Support url-safe base64 encoding.

## [4.3.3] 2021-05-03

- Test with Ruby 3 and Rails 6.1.
- Move CI to GitHub Actions.
- Correct the permissions and owner error message.
- Switch to Amazing Print.

## [4.3.2] 2020-04-04

- Ruby 2.7 fixes.

## [4.3.1] 2019-10-10

- Fix the Rails 6.0 deprecation warning for `Module#parent`, renamed to `module_parent`.

## [4.3.0] 2019-05-01

- Make the Active Record Attributes API the recommended approach on Rails 5 and above, with
  `SymmetricEncryption::EncryptedAttribute` registered as the `:encrypted` type.
- Implement type conversions for the `:encrypted` attribute type.
- Add a global setting to default `random_iv: true` for all encryption APIs.
- Only register the attribute type when running Active Record 5 or greater.

## [4.2.1] 2019-04-04

- Also accept key file permissions of `0400`, in addition to `0600`.

## [4.2.0] 2019-02-21

- Support Google Cloud Platform KMS as a keystore.
- Extract the framework-free components into `symmetric_encryption/core`, and load the ORM
  adapters lazily via `ActiveSupport.on_load`, so that gem load order no longer matters.
- Refactor the keystores onto a common file management utility module.

## [4.1.4] 2019-02-12

- Use `dirname` to create the parent path for a new configuration file.

## [4.1.3] 2019-02-03

- Generated key files are only readable by their owner.
- Add AWS to the list of available keystores in the command line help.

## [4.1.2] 2018-11-11

- Prevent encrypted attribute corruption when using the `:none` encoder.
- Fix `--rotate-keys`.
- Fix the named parameters of the `--generate` command.

## [4.1.1] 2018-10-22

- Refine the way in which gem load order is made unimportant.

## [4.1.0] 2018-10-21

- Add AWS KMS as a keystore, and refactor the keystores to support additional ones.
- Support an output buffer in `Reader#read`, and drastically reduce `Reader` and `Writer` memory
  usage.
- Compress by default when using `Writer.open`.
- Remove the dependency on Gemfile load ordering.
- JRuby fixes.

## [4.0.1] 2018-05-03

- Fix an Active Record validation regression with blank values.
- Allow the environment requested from the configuration file to be set explicitly.
- Fix the app name parameter of the `--generate` command.

## [4.0.0] 2017-08-30

- Adopt keyword arguments across the APIs that take optional arguments. `encrypt` and `decrypt`
  now require keyword arguments for anything optional.
- Replace the Rake tasks with the `symmetric-encryption` command line interface, covering
  configuration and key generation, data key rotation, key encrypting key rotation, and file
  re-encryption.
- The configuration file is now modified in place rather than generated from templates, so that
  the command line interface can update it. Back up `symmetric-encryption.yml` before upgrading.
- Migrate old configuration file formats, via `--migrate`.
- The defaults for `encoding` and `always_add_header` changed to `:base64strict` and `true`. Set
  them explicitly before upgrading to retain the previous `:base64` and `false`.
- Change `Config` into a class.
- Update to PCI DSS v3.2.

## [3.9.1] 2017-05-26

- Fix the header when a key version of 5 or higher is used together with a random IV. The
  supplied version was overridden while building the header, corrupting it.

## [3.9.0] 2017-04-25

- Deprecate MongoMapper. It is not supported with Rails 5.
- Fix key generation for the development and test environments.
- Fix `ArgumentError` when generating new random keys.
- Improve the Heroku configuration template.
- Support Ruby 2.4.

## [3.8.3] 2016-05-19

- Handle binary data that cannot be converted to UTF-8.

## [3.8.2] 2015-10-25

- Allow Rails to start even when the encryption keys are not present.

## [3.8.1] 2015-10-22

- Fix generating new keys.

## [3.8.0] 2015-10-17

- Add support for the dirty methods, such as `_changed?`, on the unencrypted method names.
- Disable the `attr_encrypted` extension when the `attr_encrypted` gem is already loaded, since
  the two conflict.
- Refactor configuration file handling and generation, and deep symbolize the configuration keys.

## [3.7.2] 2015-07-08

- Prevent `IOError: stream already closed`.

## [3.7.1] 2015-04-15

- Remove the Ruby version lock.

## [3.7.0] 2015-04-15

- Raise dedicated exceptions rather than `RuntimeError`.
- Raise `ArgumentError` for invalid parameters instead of warning.
- Unsupported options no longer cause a load error from a missing variable.

## [3.6.0] 2014-06-04

- Support encrypting keys in MongoMapper.

## [3.5.0] 2014-04-21

- Coerce empty strings to `nil`.
- Handle a missing encrypted key or iv during key generation.
- Fix the `config:add` syntax for Heroku.
- On JRuby, return an empty string rather than `nil` when the file is empty.

## [3.4.0] 2014-02-17

- Coerce attribute values on the setters.
- Fix the `decrypt_as` logic for Mongoid fields.
- Add a generator to create a Heroku configuration file:
  `rails g symmetric_encryption:heroku_config`.

## [3.3.0] 2014-01-11

- Add non-String data type support for Mongoid models.
- Add JSON and YAML serialization options, useful for hashes and arrays.
- Define the generated Active Record methods inside a module, so that `super` can be used.
- Make the highline gem a soft dependency, only required by the rake tasks that prompt for input.

## [3.2.0] 2013-12-31

- Add support for non-String data types to the Active Record extension, using the coercible gem
  to coerce values into the supplied `type`.
- Add the ability to determine whether a cipher has already been set, so that loading under Rails
  does not re-configure an already configured instance.

## [3.1.0] 2013-09-25

- Remove the binary flag. It caused the same string to encrypt to different values depending on
  the string encoding of the input.

## [3.0.3] 2013-09-20

The v3 release included the following breaking changes:

- `SymmetricEncryption.decrypt` no longer rotates through all of the decryption keys when a
  cipher fails to decrypt a value. In a small but significant number of cases it was possible to
  decrypt data with the wrong key, returning garbage rather than raising. Supply
  `SymmetricEncryption.select_cipher` to choose the cipher when a value has no header.
- Support multiple ciphers for the development, test and release environments, and allow the key
  to be supplied inline or through an environment variable, via the new `:encrypted_key` and
  `:encrypted_iv` options. Keys can therefore come from other sources, such as a directory
  service.
- `Cipher.parse_magic_header!` returns a Struct instead of an Array.
- The parameters of `Cipher.random_key_pair` and `build_header` changed.
- Configuration file formats prior to v1 are no longer supported.
- Encrypting or decrypting `nil` or `''` returns the supplied value.

## [2.2.0] 2013-07-16

- Support Rails 4 and Mongoid 4.
- Freeze the unencrypted value of an encrypted Mongoid field, so that modifying it in place with
  `gsub!` and friends cannot leave the encrypted and unencrypted values out of sync. Call `dup`
  on the value before modifying it.

## [2.0.2] 2013-06-26

- Fix a padding error on Windows.

## [2.0.1] 2013-04-22

- Fix reading an empty encrypted file, with and without a header.

## [2.0.0] 2013-04-16

- `attr_encrypted` can now specify which fields always use a random IV, for better security, and
  supports compression per encrypted database column.

## [1.1.1] 2013-04-11

- Stop encrypting the random IV. Only the encryption key needs to be hidden from an attacker.

## [1.1.0] 2013-04-10

- Stream and file encryption now generates a random key and IV for every new file or stream. The
  key and IV are encrypted with the global encryption key and stored in the header, so headers
  are now on by default for streams and files.
- Add rake tasks to encrypt and decrypt files, including an option to compress while encrypting.
- Fix versioning of encrypted files, and support setting the version to 0 for a previous key that
  was not versioned.

## [1.0.0] 2013-03-07

- Add support for Base16 (hex) encoding, and move encoding and decoding into `Cipher#encrypt` and
  `Cipher#decrypt`.
- Add Active Record and Mongoid examples.

## [0.9.1] 2012-11-05

- Add a Rails generator for the default configuration file, replacing the rake task that
  generated the key files.
- Add `:base64strict` encoding, which excludes newlines, and make it the default in generated
  configuration files.
- Add the header by default when writing to encrypted streams and files.
- Add file streaming encryption support for FasterCSV, by implementing `gets`, `pos`, `rewind`
  and `seek`.
- Add `size` and `flush`, needed by the XLS gem.
- Move Rails initialization to `before_configuration`, so that `rake db:reset` works.
- Support Ruby 1.9.

Releases prior to 0.9.1 are not covered here, and pre-releases are not listed.
