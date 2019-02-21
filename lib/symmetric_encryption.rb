require 'symmetric_encryption/core'

# Add extensions. Gems are no longer order dependent.
begin
  require 'rails'
  require 'symmetric_encryption/railtie'
rescue LoadError
end

begin
  require 'active_record'
  require 'symmetric_encryption/extensions/active_record/base'
rescue LoadError
end

begin
  require 'active_model'
  require 'symmetric_encryption/railties/symmetric_encryption_validator'
rescue LoadError
end

begin
  require 'mongoid'
  require 'symmetric_encryption/extensions/mongoid/encrypted'
rescue LoadError
end

begin
  require 'mongo_mapper'
  warn 'MongoMapper support is deprecated. Please upgrade to Mongoid.'
  require 'symmetric_encryption/extensions/mongo_mapper/plugins/encrypted_key'
rescue LoadError
end
