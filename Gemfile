source 'https://rubygems.org'

group :test do
  gem "rake"

  gem "shoulda"

  # Limited to Rails 3.2.x only because of Mongoid dependency below
  # If Mongoid Appender is not used, Rails 4 should work fine
  gem "activerecord", "~> 3.2.0"
  gem 'sqlite3', :platform => :ruby

  platforms :jruby do
    gem 'jdbc-sqlite3'
    gem 'activerecord-jdbcsqlite3-adapter'
  end

  gem "mongoid", "~> 3.1.0"
end
