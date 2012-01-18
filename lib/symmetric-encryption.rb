require 'symmetric/version'
require 'symmetric/encryption'
if defined?(Rails)
  require 'symmetric/railtie'
  require "symmetric/extensions/active_record/base"
end
