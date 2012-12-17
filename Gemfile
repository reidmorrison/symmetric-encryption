source :rubygems

group :test do
  gem "shoulda"

  gem "activerecord"
  platforms :ruby do
    gem 'sqlite3'
  end

  platforms :jruby do
    gem 'jdbc-sqlite3'
    gem 'activerecord-jdbcsqlite3-adapter'
  end

  gem "mongoid"
end
