require "symmetric_encryption/core"

# Add extensions. Gems are no longer order dependent.
begin
  require "rails"
  require "symmetric_encryption/railtie"
rescue LoadError
end

begin
  require "active_support"
  ActiveSupport.on_load(:active_record) do
    require "symmetric_encryption/active_record/attr_encrypted"
    require "symmetric_encryption/railties/symmetric_encryption_validator"

    if ActiveRecord.version >= Gem::Version.new("5.0.0")
      ActiveRecord::Type.register(:encrypted, SymmetricEncryption::ActiveRecord::EncryptedAttribute)
    end

    # Remove old way of defining attributes with Rails 7 since it conflicts with the method names.
    if ActiveRecord.version <= Gem::Version.new("7.0.0")
      ActiveRecord::Base.include(SymmetricEncryption::ActiveRecord::AttrEncrypted)
    end
  end

  ActiveSupport.on_load(:mongoid) do
    require "symmetric_encryption/railties/mongoid_encrypted"
    require "symmetric_encryption/railties/symmetric_encryption_validator"
  end
rescue LoadError
end
