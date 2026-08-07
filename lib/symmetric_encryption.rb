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
  end

  ActiveSupport.on_load(:mongoid) do
    require "symmetric_encryption/railties/mongoid_encrypted"
    require "symmetric_encryption/railties/symmetric_encryption_validator"
  end
rescue LoadError
  # Active Support is an optional dependency. Without it there is no Active Record or
  # Mongoid to hook into.
end
