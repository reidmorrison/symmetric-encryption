require 'symmetric_encryption/core'

# Add extensions. Gems are no longer order dependent.
begin
  require 'rails'
  require 'symmetric_encryption/railtie'
rescue LoadError
end

ActiveSupport.on_load(:active_record) do
  require 'symmetric_encryption/railties/attr_encrypted'
  require 'symmetric_encryption/railties/symmetric_encryption_validator'

  ActiveRecord::Base.include(SymmetricEncryption::Railties::AttrEncrypted)
end

ActiveSupport.on_load(:mongoid) do
  require 'symmetric_encryption/railties/mongoid_encrypted'
  require 'symmetric_encryption/railties/symmetric_encryption_validator'
end
