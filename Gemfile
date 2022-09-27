source "https://rubygems.org"

gemspec

gem "activerecord", "~> 7.0.0"
gem "mongoid", "~> 7.4.0"
gem "sqlite3", "~> 1.4.0", platform: :ruby
gem "google-cloud-kms", platform: :ruby

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
