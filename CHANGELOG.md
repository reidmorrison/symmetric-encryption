# Change Log

## [v4.1.0](https://github.com/rocketjob/symmetric-encryption/tree/HEAD)

[Full Changelog](https://github.com/rocketjob/symmetric-encryption/compare/v4.0.0...v4.1.0)

**Closed issues:**

- Cipher with version:1 not found in any of the configured SymmetricEncryption ciphers [\#103](https://github.com/rocketjob/symmetric-encryption/issues/103)
- Query Db? [\#102](https://github.com/rocketjob/symmetric-encryption/issues/102)
- Validating for nil is giving false in my tests/Getting Coercible::UnsupportedCoercion: Coercible::Coercer::Object\#to\_string errors [\#96](https://github.com/rocketjob/symmetric-encryption/issues/96)
- Can't get array column to encrypt [\#91](https://github.com/rocketjob/symmetric-encryption/issues/91)
- Generate files command appears to suggest wrong parameter for app name [\#90](https://github.com/rocketjob/symmetric-encryption/issues/90)
- Order preserving encryption [\#89](https://github.com/rocketjob/symmetric-encryption/issues/89)
- Issue saving non-string fields - Encrypted date test must be a value encrypted using SymmetricEncryption.encrypt [\#88](https://github.com/rocketjob/symmetric-encryption/issues/88)
- Multi-environment usage [\#87](https://github.com/rocketjob/symmetric-encryption/issues/87)
- Detect encryption version of an encrypted attribute [\#86](https://github.com/rocketjob/symmetric-encryption/issues/86)
- Documentation is out of date [\#84](https://github.com/rocketjob/symmetric-encryption/issues/84)
- Padding Check Failed [\#82](https://github.com/rocketjob/symmetric-encryption/issues/82)

**Merged pull requests:**

- Feature/aws kms [\#104](https://github.com/rocketjob/symmetric-encryption/pull/104) ([reidmorrison](https://github.com/reidmorrison))
- Add missing check ENV variable [\#101](https://github.com/rocketjob/symmetric-encryption/pull/101) ([ggwpp](https://github.com/ggwpp))
- Support output buffer in Reader\#read and drastically reduce Reader & Writer memory usage [\#98](https://github.com/rocketjob/symmetric-encryption/pull/98) ([janko-m](https://github.com/janko-m))
- Allow explicitly setting environment requested from config file [\#97](https://github.com/rocketjob/symmetric-encryption/pull/97) ([whatcould](https://github.com/whatcould))
- Documentation/fix links [\#85](https://github.com/rocketjob/symmetric-encryption/pull/85) ([tingaloo](https://github.com/tingaloo))

## [v4.0.0](https://github.com/rocketjob/symmetric-encryption/tree/v4.0.0) (2017-08-30)
[Full Changelog](https://github.com/rocketjob/symmetric-encryption/compare/v4.0.0.beta3...v4.0.0)

## [v4.0.0.beta3](https://github.com/rocketjob/symmetric-encryption/tree/v4.0.0.beta3) (2017-08-18)
[Full Changelog](https://github.com/rocketjob/symmetric-encryption/compare/v3.9.1...v4.0.0.beta3)

**Closed issues:**

- CLI not respecting --envs \(or --environments option\) [\#81](https://github.com/rocketjob/symmetric-encryption/issues/81)
- Error generating keys [\#79](https://github.com/rocketjob/symmetric-encryption/issues/79)
- Setting attribute to empty string changes it to null [\#77](https://github.com/rocketjob/symmetric-encryption/issues/77)
- Better standalone support [\#75](https://github.com/rocketjob/symmetric-encryption/issues/75)
- Confusing configuration messaging [\#66](https://github.com/rocketjob/symmetric-encryption/issues/66)
- Heroku support for non-rails apps [\#56](https://github.com/rocketjob/symmetric-encryption/issues/56)

## [v3.9.1](https://github.com/rocketjob/symmetric-encryption/tree/v3.9.1) (2017-05-26)
[Full Changelog](https://github.com/rocketjob/symmetric-encryption/compare/v3.9.0...v3.9.1)

**Closed issues:**

- Using a key version of 5 or higher in conjunction with a  random IV is corrupting the header [\#78](https://github.com/rocketjob/symmetric-encryption/issues/78)

**Merged pull requests:**

- CLI \#75  [\#76](https://github.com/rocketjob/symmetric-encryption/pull/76) ([amedeiros](https://github.com/amedeiros))

## [v3.9.0](https://github.com/rocketjob/symmetric-encryption/tree/v3.9.0) (2017-04-25)
[Full Changelog](https://github.com/rocketjob/symmetric-encryption/compare/v3.8.3...v3.9.0)

**Closed issues:**

- ArgumentError while generating new keys for heroku [\#72](https://github.com/rocketjob/symmetric-encryption/issues/72)
- Can't use unicode for key in YAML with Ruby 2.4 [\#71](https://github.com/rocketjob/symmetric-encryption/issues/71)
- Not work with ruby 2.4 [\#70](https://github.com/rocketjob/symmetric-encryption/issues/70)
- In development, I get: wrong final block length [\#69](https://github.com/rocketjob/symmetric-encryption/issues/69)
- Unknown SymmetricEncryptionValidator in RAILS\_ENV=development [\#68](https://github.com/rocketjob/symmetric-encryption/issues/68)
- Heroku Could not find generator 'symmetric\_encryption:heroku\_config [\#67](https://github.com/rocketjob/symmetric-encryption/issues/67)
- \#encrypted? returns true for a plain text string [\#63](https://github.com/rocketjob/symmetric-encryption/issues/63)
- HIPAA Compliance [\#61](https://github.com/rocketjob/symmetric-encryption/issues/61)
- new\_keys generator raises undefined method 'encrypt\_key' [\#59](https://github.com/rocketjob/symmetric-encryption/issues/59)
- How to encrypt entire files at rest? [\#58](https://github.com/rocketjob/symmetric-encryption/issues/58)
- Virus test file causes header\_present? method to fail [\#57](https://github.com/rocketjob/symmetric-encryption/issues/57)

**Merged pull requests:**

- Fix key generation for development and test enviorement [\#74](https://github.com/rocketjob/symmetric-encryption/pull/74) ([jonatasrancan](https://github.com/jonatasrancan))
- Fix error while generate new random keys and improve heroku\_config template [\#73](https://github.com/rocketjob/symmetric-encryption/pull/73) ([jonatasrancan](https://github.com/jonatasrancan))

## [v3.8.3](https://github.com/rocketjob/symmetric-encryption/tree/v3.8.3) (2016-05-19)
[Full Changelog](https://github.com/rocketjob/symmetric-encryption/compare/v3.8.2...v3.8.3)

## [v3.8.2](https://github.com/rocketjob/symmetric-encryption/tree/v3.8.2) (2015-10-26)
[Full Changelog](https://github.com/rocketjob/symmetric-encryption/compare/v3.8.1...v3.8.2)

**Closed issues:**

- Trouble generating keys [\#54](https://github.com/rocketjob/symmetric-encryption/issues/54)

## [v3.8.1](https://github.com/rocketjob/symmetric-encryption/tree/v3.8.1) (2015-10-22)
[Full Changelog](https://github.com/rocketjob/symmetric-encryption/compare/v3.8.0...v3.8.1)

## [v3.8.0](https://github.com/rocketjob/symmetric-encryption/tree/v3.8.0) (2015-10-17)
[Full Changelog](https://github.com/rocketjob/symmetric-encryption/compare/V3.7.2...v3.8.0)

**Closed issues:**

- Uniqueness validations need work [\#53](https://github.com/rocketjob/symmetric-encryption/issues/53)
- How to encrypt fields when bulk creating through db.collection.insert\(\) [\#52](https://github.com/rocketjob/symmetric-encryption/issues/52)
- Conflict with attr\_encrypted gem [\#51](https://github.com/rocketjob/symmetric-encryption/issues/51)
- NameError: uninitialized constant SymmetricEncryption [\#50](https://github.com/rocketjob/symmetric-encryption/issues/50)
- Missing dirty methods [\#49](https://github.com/rocketjob/symmetric-encryption/issues/49)
- Support for serialize [\#48](https://github.com/rocketjob/symmetric-encryption/issues/48)
- Beating the railtie config.before\_configuration [\#43](https://github.com/rocketjob/symmetric-encryption/issues/43)
- Validates Uniqueness \(discussion\) [\#38](https://github.com/rocketjob/symmetric-encryption/issues/38)

**Merged pull requests:**

- Typo Correction [\#46](https://github.com/rocketjob/symmetric-encryption/pull/46) ([jimbeaudoin](https://github.com/jimbeaudoin))

## [V3.7.2](https://github.com/rocketjob/symmetric-encryption/tree/V3.7.2) (2015-07-08)
[Full Changelog](https://github.com/rocketjob/symmetric-encryption/compare/v3.7.2...V3.7.2)

## [v3.7.2](https://github.com/rocketjob/symmetric-encryption/tree/v3.7.2) (2015-07-08)
[Full Changelog](https://github.com/rocketjob/symmetric-encryption/compare/v3.7.1...v3.7.2)

**Closed issues:**

- AES CBC without Authentication [\#47](https://github.com/rocketjob/symmetric-encryption/issues/47)

## [v3.7.1](https://github.com/rocketjob/symmetric-encryption/tree/v3.7.1) (2015-04-15)
[Full Changelog](https://github.com/rocketjob/symmetric-encryption/compare/v3.7.0...v3.7.1)

## [v3.7.0](https://github.com/rocketjob/symmetric-encryption/tree/v3.7.0) (2015-04-15)
[Full Changelog](https://github.com/rocketjob/symmetric-encryption/compare/v3.6.0...v3.7.0)

**Closed issues:**

- Regular expression search on encrypted fields. [\#45](https://github.com/rocketjob/symmetric-encryption/issues/45)
- FactoryGirl with SymmetricEncryption [\#44](https://github.com/rocketjob/symmetric-encryption/issues/44)
- Being forced to call SymmetricEncryption.reload! before encrypting or decrypting [\#42](https://github.com/rocketjob/symmetric-encryption/issues/42)
- YAML -\> Hash marshalling and unmarshalling does not appear to work [\#40](https://github.com/rocketjob/symmetric-encryption/issues/40)
- Using key with pgcrypto [\#39](https://github.com/rocketjob/symmetric-encryption/issues/39)
- Padding Check Failed on Heroku Deploy [\#31](https://github.com/rocketjob/symmetric-encryption/issues/31)

**Merged pull requests:**

- Using unsupported options causes a load error due to missing variable [\#41](https://github.com/rocketjob/symmetric-encryption/pull/41) ([johnathanludwig](https://github.com/johnathanludwig))

## [v3.6.0](https://github.com/rocketjob/symmetric-encryption/tree/v3.6.0) (2014-06-04)
[Full Changelog](https://github.com/rocketjob/symmetric-encryption/compare/V3.4.0...v3.6.0)

**Closed issues:**

- Validations and object lifecycle [\#36](https://github.com/rocketjob/symmetric-encryption/issues/36)
- Rails.root nil for config.before\_configuration in Rails 4.1 [\#35](https://github.com/rocketjob/symmetric-encryption/issues/35)
- Heroku support [\#11](https://github.com/rocketjob/symmetric-encryption/issues/11)

**Merged pull requests:**

- Fix config:add syntax for heroku [\#37](https://github.com/rocketjob/symmetric-encryption/pull/37) ([alanho](https://github.com/alanho))
- Handle a missing encrypted\_key or iv for keygen [\#34](https://github.com/rocketjob/symmetric-encryption/pull/34) ([bdmac](https://github.com/bdmac))
- Fixes output from generate\_symmetric\_key\_files [\#33](https://github.com/rocketjob/symmetric-encryption/pull/33) ([bdmac](https://github.com/bdmac))

## [V3.4.0](https://github.com/rocketjob/symmetric-encryption/tree/V3.4.0) (2014-02-17)
[Full Changelog](https://github.com/rocketjob/symmetric-encryption/compare/V3.3.0...V3.4.0)

**Closed issues:**

- Fields with decrypt\_as need typecasting on setters [\#28](https://github.com/rocketjob/symmetric-encryption/issues/28)

**Merged pull requests:**

- Fix coercion [\#29](https://github.com/rocketjob/symmetric-encryption/pull/29) ([astjohn](https://github.com/astjohn))
- Fix decrypt\_as logic for mongoid fields [\#27](https://github.com/rocketjob/symmetric-encryption/pull/27) ([astjohn](https://github.com/astjohn))

## [V3.3.0](https://github.com/rocketjob/symmetric-encryption/tree/V3.3.0) (2014-01-11)
[Full Changelog](https://github.com/rocketjob/symmetric-encryption/compare/V3.1.0...V3.3.0)

**Closed issues:**

- Can an encrypted attribute be considered unique [\#26](https://github.com/rocketjob/symmetric-encryption/issues/26)
- "highline" gem is required by rake tasks [\#24](https://github.com/rocketjob/symmetric-encryption/issues/24)
- Support for Non-String field types [\#21](https://github.com/rocketjob/symmetric-encryption/issues/21)
- Exception decrypt non encrypted string [\#20](https://github.com/rocketjob/symmetric-encryption/issues/20)
- undefined method `write\_inheritable\_hash' for ActiveRecord::Base:Class  [\#19](https://github.com/rocketjob/symmetric-encryption/issues/19)
- ActiveRecord serialize doesn't work [\#16](https://github.com/rocketjob/symmetric-encryption/issues/16)

**Merged pull requests:**

- Uses coercible gem to coerce values into the specified type [\#23](https://github.com/rocketjob/symmetric-encryption/pull/23) ([mscottford](https://github.com/mscottford))
- Define encrypted ActiveRecord methods inside a module, so we can use super [\#22](https://github.com/rocketjob/symmetric-encryption/pull/22) ([gaizka](https://github.com/gaizka))

## [V3.1.0](https://github.com/rocketjob/symmetric-encryption/tree/V3.1.0) (2013-09-25)
[Full Changelog](https://github.com/rocketjob/symmetric-encryption/compare/V3.0.3...V3.1.0)

## [V3.0.3](https://github.com/rocketjob/symmetric-encryption/tree/V3.0.3) (2013-09-20)
[Full Changelog](https://github.com/rocketjob/symmetric-encryption/compare/V2.2.0...V3.0.3)

**Closed issues:**

- Error during rails generate symmetric\_encryption:new\_keys production [\#15](https://github.com/rocketjob/symmetric-encryption/issues/15)
- Error in cipher\_selector [\#14](https://github.com/rocketjob/symmetric-encryption/issues/14)
- Cannot install gem [\#13](https://github.com/rocketjob/symmetric-encryption/issues/13)

## [V2.2.0](https://github.com/rocketjob/symmetric-encryption/tree/V2.2.0) (2013-07-16)
[Full Changelog](https://github.com/rocketjob/symmetric-encryption/compare/V2.0.2...V2.2.0)

**Closed issues:**

- user.reload != User.find\(user.id\) under certain circumstances [\#9](https://github.com/rocketjob/symmetric-encryption/issues/9)
- Should support wrap\_parameters [\#7](https://github.com/rocketjob/symmetric-encryption/issues/7)

## [V2.0.2](https://github.com/rocketjob/symmetric-encryption/tree/V2.0.2) (2013-06-26)
[Full Changelog](https://github.com/rocketjob/symmetric-encryption/compare/V2.0.1...V2.0.2)

**Closed issues:**

- Padding error on Windows. [\#10](https://github.com/rocketjob/symmetric-encryption/issues/10)

## [V2.0.1](https://github.com/rocketjob/symmetric-encryption/tree/V2.0.1) (2013-04-22)
[Full Changelog](https://github.com/rocketjob/symmetric-encryption/compare/V2.0.0...V2.0.1)

## [V2.0.0](https://github.com/rocketjob/symmetric-encryption/tree/V2.0.0) (2013-04-16)
[Full Changelog](https://github.com/rocketjob/symmetric-encryption/compare/V1.1.1...V2.0.0)

## [V1.1.1](https://github.com/rocketjob/symmetric-encryption/tree/V1.1.1) (2013-04-11)
[Full Changelog](https://github.com/rocketjob/symmetric-encryption/compare/V1.1.0...V1.1.1)

## [V1.1.0](https://github.com/rocketjob/symmetric-encryption/tree/V1.1.0) (2013-04-10)
[Full Changelog](https://github.com/rocketjob/symmetric-encryption/compare/V1.0.0...V1.1.0)

## [V1.0.0](https://github.com/rocketjob/symmetric-encryption/tree/V1.0.0) (2013-03-07)
[Full Changelog](https://github.com/rocketjob/symmetric-encryption/compare/V0.9.1...V1.0.0)

**Closed issues:**

- Security Question [\#8](https://github.com/rocketjob/symmetric-encryption/issues/8)
- undefined method `find\_or\_create\_by\_name' [\#6](https://github.com/rocketjob/symmetric-encryption/issues/6)
- Each message should use independent random IVs [\#2](https://github.com/rocketjob/symmetric-encryption/issues/2)

## [V0.9.1](https://github.com/rocketjob/symmetric-encryption/tree/V0.9.1) (2012-11-05)
**Closed issues:**

- rails generator not working [\#5](https://github.com/rocketjob/symmetric-encryption/issues/5)
- RuntimeError: Call SymmetricEncryption.load! [\#3](https://github.com/rocketjob/symmetric-encryption/issues/3)
- Problems during rake db:reset [\#1](https://github.com/rocketjob/symmetric-encryption/issues/1)



\* *This Change Log was automatically generated by [github_changelog_generator](https://github.com/skywinder/Github-Changelog-Generator)*
