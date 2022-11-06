require_relative "../test_helper"

ActiveRecord::Base.configurations = YAML.safe_load(ERB.new(File.read("test/config/database.yml")).result)
ActiveRecord::Base.establish_connection(:test)

ActiveRecord::Schema.define version: 0 do
  create_table :people, force: true do |t|
    t.string :name
    t.string :age
    t.string :address
    t.string :integer_value
    t.string :float_value
    t.string :decimal_value
    t.string :datetime_value
    t.string :time_value
    t.string :date_value
    t.string :true_value
    t.string :false_value
  end
end

class Person < ActiveRecord::Base
  attribute :name, :encrypted, random_iv: false
  attribute :age, :encrypted, type: :integer, random_iv: false
  attribute :address, :encrypted
  attribute :integer_value, :encrypted, type: :integer
  attribute :float_value, :encrypted, type: :float
  attribute :decimal_value, :encrypted, type: :decimal
  attribute :datetime_value, :encrypted, type: :datetime
  attribute :time_value, :encrypted, type: :time
  attribute :date_value, :encrypted, type: :date
  attribute :true_value, :encrypted, type: :boolean
  attribute :false_value, :encrypted, type: :boolean
end

class EncryptedAttributeTest < Minitest::Test
  describe "SymmetricEncryption::ActiveRecord::EncryptedAttribute" do
    before do
      skip "Custom attribute types support starting from Rails 5" if ActiveRecord.version < Gem::Version.new("5.0.0")
      Person.delete_all
    end

    let(:person_name) { "Abcd Efgh" }
    let(:encrypted_name) { "QEVuQwIAsvPWRoF61GxkAr5+f+eTfg==" }
    let(:age) { 23 }
    let(:encrypted_age) { "QEVuQwIA/YvnMQ8QAoDpiOaIAmrUkg==" }
    let(:address) { "Some test value" }

    let(:integer_value) { 13_456 }
    let(:float_value) { 88.12345 }
    let(:decimal_value) { BigDecimal("22.51") }
    let(:datetime_value) { DateTime.new(2001, 11, 26, 20, 55, 54, "-5") }
    let(:time_value) { Time.new(2013, 1, 1, 22, 30, 0, "-04:00") }
    let(:date_value) { Date.new(1927, 4, 2) }

    let :person do
      Person.create(
        name:           person_name,
        age:            age,
        address:        address,
        integer_value:  integer_value,
        float_value:    float_value,
        decimal_value:  decimal_value,
        datetime_value: datetime_value,
        time_value:     time_value,
        date_value:     date_value,
        true_value:     true,
        false_value:    false
      )
    end

    it "stores encrypted string value" do
      assert_equal encrypted_name, person.read_attribute_before_type_cast(:name)
    end

    it "reads unencrypted string value" do
      assert_equal person_name, person.reload.name
    end

    it "stores encrypted age value" do
      assert_equal encrypted_age, person.read_attribute_before_type_cast(:age)
    end

    it "reads unencrypted integer value" do
      assert_equal age, person.reload.age
    end

    it "stores nil value" do
      person = Person.create(name: nil)
      assert_nil person.reload.name
      assert_nil person.read_attribute_before_type_cast(:name)
    end

    it "stores a value which can later be decrypted" do
      person            = Person.create(address: address)
      encrypted_address = person.read_attribute_before_type_cast(:address)
      assert_equal address, SymmetricEncryption.decrypt(encrypted_address)
    end

    it "uses different iv each time" do
      person.update(address: address)
      address1 = person.read_attribute_before_type_cast(:address)
      person.update(address: address)
      address2 = person.read_attribute_before_type_cast(:address)
      iv1      = SymmetricEncryption.header(address1).iv
      iv2      = SymmetricEncryption.header(address2).iv
      refute_equal iv1, iv2
    end

    it "reports whether it has changed" do
      person.name # Call field so decryption happens
      assert !person.name_changed?

      person.name = "Abcde fghij"
      assert person.name_changed?
    end

    it "reports whether it has changed since last save" do
      person.reload
      person.name # Call field so decryption happens
      assert !person.saved_change_to_name?

      person.update!(address: "Some other test value")
      assert !person.saved_change_to_name?
      assert person.saved_change_to_address?
    end

    describe "types" do
      it "serializes" do
        assert_equal person_name, person.name
        assert_equal age, person.age
        assert_equal address, person.address

        assert_equal integer_value, person.integer_value
        assert_equal float_value, person.float_value
        assert_equal decimal_value, person.decimal_value
        assert_equal datetime_value, person.datetime_value
        assert_equal time_value, person.time_value
        assert_equal date_value, person.date_value
        assert_equal true, person.true_value
        assert_equal false, person.false_value
      end
    end
  end
end
