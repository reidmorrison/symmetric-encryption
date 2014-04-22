source 'https://rubygems.org'

gem 'rake'
gem 'sync_attr'
gem 'thread_safe'
gem 'semantic_logger'

# Used by rake task for user to enter text to be encrypted
gem 'highline'
gem 'coercible'

if RUBY_VERSION.to_f == 1.9
  gem 'activerecord', '~> 3.0'
  gem 'mongoid', '~> 3.0'
else
  # attr_encrypted
  gem 'activerecord', '>= 4.0'
  # For Mongoid encryption extensions
  gem 'bson'
  gem 'mongoid', '>= 4.0.0.alpha1'
end

gem 'sqlite3', :platform => :ruby
gem 'jdbc-sqlite3', :platform => :jruby
gem 'activerecord-jdbcsqlite3-adapter', :platform => :jruby

group :development do
  gem 'awesome_print'
  gem 'travis-lint'
end

group :test do
  if RUBY_VERSION.to_f == 1.9
    gem 'minitest', '~> 3.0'
    gem 'shoulda', '~> 2.0'
  else
    gem 'minitest', '~> 4.0'
    gem 'shoulda'
  end
  gem 'mocha'
end
