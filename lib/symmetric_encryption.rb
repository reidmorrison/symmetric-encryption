require 'symmetric_encryption/core'

# Add extensions. Gems are no longer order dependent.
begin
  require 'rails'
  require 'symmetric_encryption/railtie'
rescue LoadError
end

begin
  require 'active_record'
  require 'symmetric_encryption/railties/attr_encrypted'
  require 'symmetric_encryption/railties/symmetric_encryption_validator'

  ActiveRecord::Base.include(SymmetricEncryption::Railties::AttrEncrypted)
rescue LoadError
end

begin
  require 'mongoid'
  require 'symmetric_encryption/railties/mongoid_encrypted'
  require 'symmetric_encryption/railties/symmetric_encryption_validator'
rescue LoadError
end
