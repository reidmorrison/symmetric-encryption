# Used for compression
require 'zlib'
# Used to coerce data types between string and their actual types
require 'coercible'

require 'symmetric_encryption/version'
require 'symmetric_encryption/cipher'
require 'symmetric_encryption/symmetric_encryption'
require 'symmetric_encryption/exception'

# @formatter:off
module SymmetricEncryption
  autoload :Coerce,                 'symmetric_encryption/coerce'
  autoload :Config,                 'symmetric_encryption/config'
  autoload :Encoder,                'symmetric_encryption/encoder'
  autoload :Generator,              'symmetric_encryption/generator'
  autoload :Header,                 'symmetric_encryption/header'
  autoload :Key,                    'symmetric_encryption/key'
  autoload :Reader,                 'symmetric_encryption/reader'
  autoload :RSAKey,                 'symmetric_encryption/rsa_key'
  autoload :Writer,                 'symmetric_encryption/writer'
  autoload :CLI,                    'symmetric_encryption/cli'
  autoload :Keystore,               'symmetric_encryption/keystore'
  module Utils
    autoload :Generate,             'symmetric_encryption/utils/generate'
    autoload :ReEncryptFiles,       'symmetric_encryption/utils/re_encrypt_files'
  end
end
# @formatter:on

# Add support for other libraries only if they have already been loaded
require 'symmetric_encryption/railtie' if defined?(Rails)
if defined?(ActiveRecord::Base) && !defined?(AttrEncrypted::Version)
  require 'symmetric_encryption/extensions/active_record/base'
end
require 'symmetric_encryption/railties/symmetric_encryption_validator' if defined?(ActiveModel)
require 'symmetric_encryption/extensions/mongoid/encrypted' if defined?(Mongoid)
if defined?(MongoMapper)
  warn 'MongoMapper support is deprecated. Upgrade to Mongoid.'
  require 'symmetric_encryption/extensions/mongo_mapper/plugins/encrypted_key'
end
