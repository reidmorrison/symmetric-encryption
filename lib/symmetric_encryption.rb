require 'symmetric_encryption/version'
require 'symmetric_encryption/cipher'
require 'symmetric_encryption/symmetric_encryption'
require 'symmetric_encryption/reader'
require 'symmetric_encryption/writer'
require 'zlib'
if defined?(Rails)
  require 'symmetric_encryption/railtie'
end
# attr_encrypted and Encrypted validator
if defined?(ActiveRecord::Base)
  require 'symmetric_encryption/extensions/active_record/base'
  require 'symmetric_encryption/railties/symmetric_encryption_validator'
end

# field encryption for Mongoid
if defined?(Mongoid)
  require 'symmetric_encryption/extensions/mongoid/fields'
end
