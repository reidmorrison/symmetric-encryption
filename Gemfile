source 'https://rubygems.org'

gemspec

gem 'activerecord', '~> 6.0.0'
gem 'activerecord-jdbcsqlite3-adapter', '~> 60.0', platform: :jruby
gem 'mongoid', '~> 7.1.0'
gem 'sqlite3', '~> 1.4.0', platform: :ruby

gem 'appraisal'
gem 'awesome_print'
gem 'minitest'
gem 'minitest-stub_any_instance'
gem 'rake'

# Optional gem used by rake task for user to enter text to be encrypted
gem 'highline'

gem 'jdbc-sqlite3', platform: :jruby

# Soft dependency, only required when storing encryption keys in AWS KMS
gem 'aws-sdk-kms'

gem 'google-cloud-kms'
gem 'google-protobuf', '~> 3.7', platform: :ruby

group :development do
  gem 'rubocop'
end
