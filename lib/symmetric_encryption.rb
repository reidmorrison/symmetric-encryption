require "symmetric_encryption/core"

# Add extensions. Gems are no longer order dependent.
begin
  require "rails"
  require "symmetric_encryption/railtie"
rescue LoadError
  # Rails is an optional dependency. Standalone Ruby apps do not need the Railtie.
end

begin
  require "active_support"
  ActiveSupport.on_load(:active_record) do
    require "symmetric_encryption/railties/symmetric_encryption_validator"

    ActiveRecord::Type.register(:encrypted, SymmetricEncryption::ActiveRecord::EncryptedAttribute)

    # Filters encrypted attributes out of `inspect` and the Rails logs. Prepended to Active Record
    # itself, rather than to each model, so that it applies to every model without anything having
    # to be declared in the model.
    singleton_class.prepend(SymmetricEncryption::ActiveRecord::AutoFilteredAttributes)
  end

  ActiveSupport.on_load(:mongoid) do
    require "symmetric_encryption/railties/mongoid_encrypted"
    require "symmetric_encryption/railties/symmetric_encryption_validator"
  end
rescue LoadError
  # Active Support is an optional dependency. Without it there is no Active Record or
  # Mongoid to hook into.
end
