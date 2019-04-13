require_relative '../test_helper'

ActiveRecord::Base.configurations = YAML.safe_load(ERB.new(IO.read('test/config/database.yml')).result)
ActiveRecord::Base.establish_connection(:test)

ActiveRecord::Schema.define version: 0 do
  create_table :people, force: true do |t|
    t.string :name
    t.string :age
    t.string :address
  end
end

class Person < ActiveRecord::Base
  attribute :name, SymmetricEncryption::EncryptedStringType.new
  attribute :age,  SymmetricEncryption::EncryptedStringType.new(encrypt_params: {type: :integer}, decrypt_params: {type: :integer})
  attribute :address, SymmetricEncryption::EncryptedStringType.new(encrypt_params: {random_iv: true})
end

class EncryptedStringTypeTest < Minitest::Test
  describe 'SymmetricEncryption::EncryptedStringType' do
    before do
      if ActiveRecord.version < Gem::Version.new('5.0.0')
        skip 'Custom attribute types support starting from Rails 5'
      end
    end

    let(:person) {
      Person.create(name: person_name, age: age)
    }

    let(:person_name) {
      'Abcd Efgh'
    }
    let(:encrypted_name) {
      "QEVuQwIAsvPWRoF61GxkAr5+f+eTfg=="
    }

    let(:age) {
      23
    }

    let(:encrypted_age) {
      "QEVuQwIA/YvnMQ8QAoDpiOaIAmrUkg=="
    }

    let(:address) {
      'Some test value'
    }

    it 'stores encrypted string value' do
      assert_equal encrypted_name, person.read_attribute_before_type_cast(:name)
    end

    it 'reads unencrypted string value' do
      assert_equal person_name, person.reload.name
    end

    it 'stores encrypted age value' do
      assert_equal encrypted_age, person.read_attribute_before_type_cast(:age)
    end

    it 'reads unencrypted string value' do
      assert_equal age, person.reload.age
    end

    it 'stores nil value' do
      person = Person.create(name: nil)
      assert_nil person.reload.name
      assert_nil person.read_attribute_before_type_cast(:name)
    end

    it 'stores a value which can later be decrypted' do
      person = Person.create(address: address)
      encrypted_address = person.read_attribute_before_type_cast(:address)
      assert_equal address, SymmetricEncryption.decrypt(encrypted_address)
    end

    it 'uses different iv each time' do
      person.update(address: address)
      address1 = person.read_attribute_before_type_cast(:address)
      person.update(address: address)
      address2 = person.read_attribute_before_type_cast(:address)
      iv1 = SymmetricEncryption.header(address1).iv
      iv2 = SymmetricEncryption.header(address2).iv
      refute_equal iv1, iv2
    end
  end
end
