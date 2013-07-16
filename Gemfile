source 'https://rubygems.org'

group :test do
  gem 'rake'
  gem 'shoulda'

  gem 'activerecord'
  gem 'sqlite3', :platform => :ruby

  platforms :jruby do
    gem 'jdbc-sqlite3'
    gem 'activerecord-jdbcsqlite3-adapter'
  end

  # Use Mongo as the database with Mongoid as the Object Document Mapper
  # Edge has support for Rails 4
  gem 'mongoid', git: 'https://github.com/mongoid/mongoid.git'
  gem 'awesome_print'
end
