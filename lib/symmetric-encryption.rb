require 'symmetric/version'
require 'symmetric/cipher'
require 'symmetric/encryption'
require 'symmetric/encryption_reader'
require 'symmetric/encryption_writer'
require 'zlib'
if defined?(Rails)
  require 'symmetric/railtie'
end
# attr_encrypted and Encrypted validator
if defined?(ActiveRecord::Base)
  require 'symmetric/extensions/active_record/base'
  require 'symmetric/railties/symmetric_encrypted_validator'
end

# field encryption for Mongoid
if defined?(Mongoid)
  require 'symmetric/extensions/mongoid/fields'
end
