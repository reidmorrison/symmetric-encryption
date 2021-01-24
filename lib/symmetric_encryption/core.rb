# Used for compression
require "zlib"
# Used to coerce data types between string and their actual types
require "coercible"

require "symmetric_encryption/version"
require "symmetric_encryption/cipher"
require "symmetric_encryption/symmetric_encryption"
require "symmetric_encryption/exception"

# @formatter:off
module SymmetricEncryption
  autoload :Coerce,                 "symmetric_encryption/coerce"
  autoload :Config,                 "symmetric_encryption/config"
  autoload :Encoder,                "symmetric_encryption/encoder"
  autoload :EncryptedStringType,    "symmetric_encryption/types/encrypted_string_type"
  autoload :Generator,              "symmetric_encryption/generator"
  autoload :Header,                 "symmetric_encryption/header"
  autoload :Key,                    "symmetric_encryption/key"
  autoload :Reader,                 "symmetric_encryption/reader"
  autoload :RSAKey,                 "symmetric_encryption/rsa_key"
  autoload :Writer,                 "symmetric_encryption/writer"
  autoload :CLI,                    "symmetric_encryption/cli"
  autoload :Keystore,               "symmetric_encryption/keystore"
  module ActiveRecord
    autoload :EncryptedAttribute,   "symmetric_encryption/active_record/encrypted_attribute"
  end

  module Utils
    autoload :Aws,                  "symmetric_encryption/utils/aws"
    autoload :Files,                "symmetric_encryption/utils/files"
    autoload :ReEncryptFiles,       "symmetric_encryption/utils/re_encrypt_files"
  end
end
# @formatter:on
