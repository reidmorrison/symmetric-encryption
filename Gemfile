source "https://rubygems.org"

gemspec

gem "activerecord", "~> 6.1.0"
gem "activerecord-jdbcsqlite3-adapter", "~> 61.0", platform: :jruby
gem "sqlite3", "~> 1.4.0", platform: :ruby

gem "amazing_print"
gem "appraisal"
gem "minitest"
gem "minitest-stub_any_instance"
gem "rake"

# Optional gem used by rake task for user to enter text to be encrypted
gem "highline"

# Soft dependency, only required when storing encryption keys in AWS KMS
gem "aws-sdk-kms"

group :development do
  gem "rubocop"
end
