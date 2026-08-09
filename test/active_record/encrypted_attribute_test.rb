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
    t.string :versioned_value
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
  # Encrypted with a key of its own, rather than the primary one.
  attribute :versioned_value, :encrypted, version: 6
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

    # Issue #62. A `date_select` submits one field per parameter, which Active Record collects into
    # a Hash keyed by parameter position and assigns in one go.
    describe "multiparameter assignment" do
      let(:date_params) { {"date_value(1i)" => "1975", "date_value(2i)" => "11", "date_value(3i)" => "9"} }

      let :datetime_params do
        {"datetime_value(1i)" => "1975", "datetime_value(2i)" => "11", "datetime_value(3i)" => "9",
         "datetime_value(4i)" => "13", "datetime_value(5i)" => "45"}
      end

      let :time_params do
        {"time_value(1i)" => "2000", "time_value(2i)" => "1", "time_value(3i)" => "1",
         "time_value(4i)" => "13", "time_value(5i)" => "45"}
      end

      it "casts the submitted parameters to the declared type" do
        unsaved = Person.new(date_params.merge(datetime_params).merge(time_params))

        assert_equal Date.new(1975, 11, 9), unsaved.date_value
        assert_equal DateTime.new(1975, 11, 9, 13, 45, 0, "+0"), unsaved.datetime_value
        assert_equal Time.utc(2000, 1, 1, 13, 45, 0), unsaved.time_value
      end

      it "reads back what was submitted" do
        record = Person.create!(date_params.merge(datetime_params).merge(time_params)).reload

        assert_equal Date.new(1975, 11, 9), record.date_value
        assert_equal DateTime.new(1975, 11, 9, 13, 45, 0, "+0"), record.datetime_value
        assert_equal Time.utc(2000, 1, 1, 13, 45, 0), record.time_value
      end

      it "casts an incomplete assignment to nil, as Active Record does" do
        unsaved = Person.new("date_value(1i)" => "1975", "date_value(2i)" => "", "date_value(3i)" => "")

        assert_nil unsaved.date_value
      end

      it "rolls an out of range date over, as Active Record does" do
        unsaved = Person.new("date_value(1i)" => "1975", "date_value(2i)" => "2", "date_value(3i)" => "31")

        assert_equal Date.new(1975, 3, 3), unsaved.date_value
      end

      it "did not come from the user, so that validations report on the cast value" do
        unsaved = Person.new(date_params)

        refute_predicate unsaved, :date_value_came_from_user?
        assert_predicate Person.new(date_value: "1975-11-09"), :date_value_came_from_user?
      end

      it "keeps a Hash assigned to a json or yaml attribute" do
        # Only a date or a time can be assigned in parameters, so a Hash is a value everywhere else.
        unsaved = Person.new(json_value: {"a" => 1}, yaml_value: {"b" => 2})

        assert_equal({"a" => 1}, unsaved.json_value)
        assert_equal({"b" => 2}, unsaved.yaml_value)
        assert_predicate unsaved, :json_value_came_from_user?
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

# Encrypting one attribute with a key of its own, by naming the version of the cipher to use.
class EncryptedAttributeVersionTest < Minitest::Test
  describe SymmetricEncryption::ActiveRecord::EncryptedAttribute do
    let :person do
      Person.create!(versioned_value: "secret", address: "primary")
    end

    def raw_value(record, column)
      Person.connection.select_value("SELECT #{column} FROM people WHERE id = #{record.id}")
    end

    it "encrypts with the version declared" do
      assert_equal 6, SymmetricEncryption.header(raw_value(person, "versioned_value")).version
    end

    it "encrypts other attributes with the primary cipher" do
      assert_equal SymmetricEncryption.cipher.version,
                   SymmetricEncryption.header(raw_value(person, "address")).version
    end

    it "reads the value back" do
      assert_equal "secret", Person.find(person.id).versioned_value
    end

    it "raises when no cipher has the version declared" do
      assert_raises SymmetricEncryption::CipherError do
        SymmetricEncryption::ActiveRecord::EncryptedAttribute.new(version: 99).serialize("value")
      end
    end
  end
end
