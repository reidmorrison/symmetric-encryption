# Add an ActiveModel Validator
#
# Example:
#  class MyModel < ActiveRecord::Base
#    validates :encrypted_ssn, :symmetric_encrypted => true
#  end
#
#  m = MyModel.new
#  m.valid?
#  #  => false
#  m.encrypted_ssn = Symmetric::Encryption.encrypt('123456789')
#  m.valid?
#  #  => true
class SymmetricEncryptedValidator < ActiveModel::EachValidator
  def validate_each(record, attribute, value)
    record.errors.add(attribute, "must be a value encrypted using Symmetric::Encryption.encrypt") unless Symmetric::Encryption.encrypted?(value)
  end
end
