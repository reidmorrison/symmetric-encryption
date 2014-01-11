# Used for compression
require 'zlib'
# Used to coerce data types between string and their actual types
require 'coercible'

require 'symmetric_encryption/version'
require 'symmetric_encryption/cipher'
require 'symmetric_encryption/symmetric_encryption'

module SymmetricEncryption
  autoload :Reader, 'symmetric_encryption/reader'
  autoload :Writer, 'symmetric_encryption/writer'
end
if defined?(Rails)
  require 'symmetric_encryption/railtie'
end

require 'symmetric_encryption/extensions/active_record/base' if defined?(ActiveRecord::Base)
require 'symmetric_encryption/railties/symmetric_encryption_validator' if defined?(ActiveModel)
require 'symmetric_encryption/mongoid' if defined?(Mongoid)
