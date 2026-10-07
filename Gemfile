source "https://rubygems.org"

gemspec

gem "activerecord", "~> 8.0.0"
gem "activerecord-jdbcsqlite3-adapter", "~> 80.0.pre1", platform: :jruby
gem "google-cloud-kms"
gem "jdbc-sqlite3", platform: :jruby
gem "mongoid", "~> 9.0.0"
# Rails 7.2 and 8.0 pass quirks_mode to JSON.generate, which json 3 rejects.
gem "json", "< 3"
gem "sqlite3", platform: :ruby

gem "amazing_print"
gem "appraisal"
gem "minitest"
gem "minitest-stub_any_instance"
gem "rake"
gem "rubocop"
gem "rubocop-minitest"
gem "rubocop-rake"
gem "simplecov", require: false
gem "solargraph", require: false, platform: :ruby

# Optional gem used by rake task for user to enter text to be encrypted
gem "highline"

# Soft dependency, only required when storing encryption keys in AWS KMS
gem "aws-sdk-kms"
