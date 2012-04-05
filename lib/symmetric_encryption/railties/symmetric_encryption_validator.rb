# Add an ActiveModel Validator
#
# Example:
#  class MyModel < ActiveRecord::Base
#    validates :encrypted_ssn, :symmetric_encryption => true
#  end
#
#  m = MyModel.new
#  m.valid?
#  #  => false
#  m.encrypted_ssn = SymmetricEncryption.encrypt('123456789')
#  m.valid?
#  #  => true
class SymmetricEncryptionValidator < ActiveModel::EachValidator
  def validate_each(record, attribute, value)
    record.errors.add(attribute, "must be a value encrypted using SymmetricEncryption.encrypt") unless SymmetricEncryption.encrypted?(value)
  end
end
