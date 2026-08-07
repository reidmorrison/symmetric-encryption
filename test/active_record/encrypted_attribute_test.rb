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
    t.string :json_value
    t.string :yaml_value
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
  attribute :json_value, :encrypted, type: :json
  attribute :yaml_value, :encrypted, type: :yaml
end

# Uncastable values are reported by the same validations as an unencrypted attribute.
class ValidatedPerson < ActiveRecord::Base
  self.table_name = "people"

  attribute :age, :encrypted, type: :integer

  validates :age, numericality: {allow_nil: true}
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

      refute_predicate person, :name_changed?

      person.name = "Abcde fghij"

      assert_predicate person, :name_changed?
    end

    it "reports whether it has changed since last save" do
      person.reload
      person.name # Call field so decryption happens

      refute_predicate person, :saved_change_to_name?

      person.update!(address: "Some other test value")

      refute_predicate person, :saved_change_to_name?
      assert_predicate person, :saved_change_to_address?
    end

    describe "casting on assignment" do
      it "casts a string to the declared type before it has been saved" do
        unsaved = Person.new(
          integer_value:  "13456",
          float_value:    "88.12345",
          decimal_value:  "22.51",
          datetime_value: "2001-11-26T20:55:54-05:00",
          date_value:     "1927-04-02",
          true_value:     "true",
          false_value:    "false"
        )

        assert_equal integer_value, unsaved.integer_value
        assert_equal float_value, unsaved.float_value
        assert_equal decimal_value, unsaved.decimal_value
        assert_equal datetime_value, unsaved.datetime_value
        assert_equal date_value, unsaved.date_value
        # rubocop:disable Minitest/AssertTruthy, Minitest/RefuteFalse
        # The point of these two is the exact value, not truthiness: :boolean must cast to true and false.
        assert_equal true, unsaved.true_value
        assert_equal false, unsaved.false_value
        # rubocop:enable Minitest/AssertTruthy, Minitest/RefuteFalse
      end

      it "keeps the date when casting a time" do
        # Unlike ActiveModel::Type::Time, which is for time columns and resets the date to 2000-01-01.
        assert_equal time_value, Person.new(time_value: "2013-01-01 22:30:00 -0400").time_value
      end

      it "casts a value that is already of the declared type" do
        unsaved = Person.new(integer_value: integer_value, date_value: date_value, time_value: time_value)

        assert_equal integer_value, unsaved.integer_value
        assert_equal date_value, unsaved.date_value
        assert_equal time_value, unsaved.time_value
      end

      it "casts to string by default" do
        assert_equal "55", Person.new(name: 55).name
        assert_equal "true", Person.new(name: true).name
      end

      it "leaves json and yaml values as they were assigned" do
        # Matches Active Record's own :json type, which does not parse strings on assignment either.
        unsaved = Person.new(json_value: {"a" => 1}, yaml_value: [1, 2])

        assert_equal({"a" => 1}, unsaved.json_value)
        assert_equal [1, 2], unsaved.yaml_value
      end

      it "casts a blank string to nil for every type other than string" do
        unsaved = Person.new(
          name:          "",
          integer_value: "",
          float_value:   "",
          decimal_value: "",
          date_value:    "",
          time_value:    " ",
          true_value:    ""
        )

        assert_equal "", unsaved.name
        assert_nil unsaved.integer_value
        assert_nil unsaved.float_value
        assert_nil unsaved.decimal_value
        assert_nil unsaved.date_value
        assert_nil unsaved.time_value
        assert_nil unsaved.true_value
      end

      it "casts an uncastable value the way Active Record does, without raising" do
        unsaved = Person.new(integer_value: "abc", float_value: "abc", decimal_value: "abc", date_value: "abc",
                             datetime_value: "abc", time_value: "abc", true_value: "abc")

        assert_equal 0, unsaved.integer_value
        assert_in_delta 0.0, unsaved.float_value
        assert_equal BigDecimal(0), unsaved.decimal_value
        assert_nil unsaved.date_value
        assert_nil unsaved.datetime_value
        assert_nil unsaved.time_value
        assert unsaved.true_value
      end

      it "truncates a partially numeric string, as Active Record does" do
        assert_equal 12, Person.new(integer_value: "12abc").integer_value
      end

      it "does not report a change when the same value is assigned as a string" do
        person.reload.age

        refute_predicate person, :age_changed?

        person.age = "23"

        refute_predicate person, :age_changed?
      end

      it "reports a validation error rather than raising for an uncastable value" do
        record = ValidatedPerson.new(age: "abc")

        refute_predicate record, :valid?
        assert_equal ["is not a number"], record.errors[:age]
        assert_equal "abc", record.age_before_type_cast
      end

      it "stores nil when a blank string is assigned to a numeric attribute" do
        record = Person.create!(integer_value: "")

        assert_nil record.reload.integer_value
        assert_nil record.read_attribute_before_type_cast(:integer_value)
      end

      it "reads back a value that was assigned as a string" do
        record = Person.create!(integer_value: "13456", date_value: "1927-04-02")

        assert_equal integer_value, record.reload.integer_value
        assert_equal date_value, record.date_value
      end

      it "rejects a type it cannot cast to when the attribute is declared" do
        error = assert_raises ArgumentError do
          SymmetricEncryption::ActiveRecord::EncryptedAttribute.new(type: :int)
        end

        assert_includes error.message, "Invalid type: :int"
      end

      it "casts before encrypting, so that a value written directly can still be read back" do
        record = Person.create!
        record.update_column(:integer_value, "abc")

        assert_equal 0, record.reload.integer_value
      end
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
        # rubocop:disable Minitest/AssertTruthy, Minitest/RefuteFalse
        # The point of these two is the exact value, not truthiness: :boolean must coerce back to true and false.
        assert_equal true, person.true_value
        assert_equal false, person.false_value
        # rubocop:enable Minitest/AssertTruthy, Minitest/RefuteFalse
      end
    end
  end
end
