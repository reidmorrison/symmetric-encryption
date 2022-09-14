require_relative "test_helper"

if ActiveRecord.version <= Gem::Version.new("7.0.4")

  ActiveRecord::Base.configurations = YAML.safe_load(ERB.new(IO.read("test/config/database.yml")).result)
  ActiveRecord::Base.establish_connection(:test)

  # @formatter:off
ActiveRecord::Schema.define version: 0 do
  create_table :users, force: true do |t|
    t.string :encrypted_bank_account_number
    t.string :encrypted_social_security_number
    t.string :encrypted_string_value
    t.text   :encrypted_long_string_value
    t.text   :encrypted_binary_string_value
    t.text   :encrypted_data_yaml
    t.text   :encrypted_data_json
    t.string :name
    t.string :encrypted_unsupported_option

    t.string :encrypted_integer_value
    t.string :encrypted_float_value
    t.string :encrypted_decimal_value
    t.string :encrypted_datetime_value
    t.string :encrypted_time_value
    t.string :encrypted_date_value
    t.string :encrypted_true_value
    t.string :encrypted_false_value

    t.string :encrypted_text
    t.string :encrypted_number
  end

  create_table :unique_users, force: true do |t|
    t.string :encrypted_email
    t.string :encrypted_username
  end
end

class User < ActiveRecord::Base
  attr_encrypted :bank_account_number,    random_iv: false
  attr_encrypted :social_security_number, random_iv: false
  attr_encrypted :string_value,           random_iv: true
  attr_encrypted :long_string_value,      random_iv: true, compress: true
  attr_encrypted :binary_string_value,    random_iv: true, compress: true
  attr_encrypted :data_yaml,              random_iv: true, compress: true, type: :yaml
  attr_encrypted :data_json,              random_iv: true, compress: true, type: :json

  attr_encrypted :integer_value,  type: :integer,  random_iv: true
  attr_encrypted :float_value,    type: :float,    random_iv: true
  attr_encrypted :decimal_value,  type: :decimal,  random_iv: true
  attr_encrypted :datetime_value, type: :datetime, random_iv: true
  attr_encrypted :time_value,     type: :time,     random_iv: true
  attr_encrypted :date_value,     type: :date,     random_iv: true
  attr_encrypted :true_value,     type: :boolean,  random_iv: true
  attr_encrypted :false_value,    type: :boolean,  random_iv: true

  validates :encrypted_bank_account_number,    symmetric_encryption: true
  validates :encrypted_social_security_number, symmetric_encryption: true

  attr_encrypted :text,           type: :string,  random_iv: true
  attr_encrypted :number,         type: :integer, random_iv: true

  validates      :text, format: {with: /\A[a-zA-Z ]+\z/, message: "only allows letters"}, presence: true
  validates      :number, presence: true
end

class UniqueUser < ActiveRecord::Base
  attr_encrypted :email, random_iv: false
  attr_encrypted :username, random_iv: false

  validates_uniqueness_of :encrypted_email,    allow_blank: true, if: :encrypted_email_changed?
  validates_uniqueness_of :encrypted_username, allow_blank: true, if: :encrypted_username_changed?

  validates :username,
            length:      {in: 3..20},
            format:      {with: /\A[\w\-]+\z/},
            allow_blank: true
end
# @formatter:on

  #
  # Unit Test for attr_encrypted extensions in ActiveRecord
  #
  class ActiveRecordTest < Minitest::Test
    INTEGER_VALUE       = 12
    FLOAT_VALUE         = 88.12345
    DECIMAL_VALUE       = BigDecimal("22.51")
    DATETIME_VALUE      = DateTime.new(2001, 11, 26, 20, 55, 54, "-5")
    TIME_VALUE          = Time.new(2013, 1, 1, 22, 30, 0, "-04:00")
    DATE_VALUE          = Date.new(1927, 4, 2)
    STRING_VALUE        = "A string containing some data to be encrypted with a random initialization vector".freeze
    LONG_STRING_VALUE   = "A string containing some data to be encrypted with a random initialization vector and compressed since it takes up so much space in plain text form".freeze
    BINARY_STRING_VALUE = "Non-UTF8 Binary \x92 string".force_encoding("BINARY")

    describe "ActiveRecord" do
      let :bank_account_number do
        "1234567890"
      end

      let :bank_account_number_encrypted do
        "QEVuQwIAL94ArJeFlJrZp6SYsvoOGA=="
      end

      let :social_security_number do
        "987654321"
      end

      let :social_security_number_encrypted do
        "QEVuQwIAS+8X1NRrqdfEIQyFHVPuVA=="
      end

      let :person_name do
        "Joe Bloggs"
      end

      let :hash_data do
        {a: "A", b: "B"}
      end

      let :user do
        User.new(
          # Encrypted Attribute
          bank_account_number: bank_account_number,
          # Encrypted Attribute
          social_security_number: social_security_number,
          name:                   person_name,
          # data type specific fields
          string_value:        STRING_VALUE,
          long_string_value:   LONG_STRING_VALUE,
          binary_string_value: BINARY_STRING_VALUE,
          integer_value:       INTEGER_VALUE,
          float_value:         FLOAT_VALUE,
          decimal_value:       DECIMAL_VALUE,
          datetime_value:      DATETIME_VALUE,
          time_value:          TIME_VALUE,
          date_value:          DATE_VALUE,
          true_value:          true,
          false_value:         false,
          data_yaml:           hash_data.dup,
          data_json:           hash_data.dup,
          text:                "hello",
          number:              "21"
        )
      end

      it "has encrypted methods" do
        assert_equal true, user.respond_to?(:encrypted_bank_account_number)
        assert_equal true, user.respond_to?(:bank_account_number)
        assert_equal true, user.respond_to?(:encrypted_social_security_number)
        assert_equal true, user.respond_to?(:social_security_number)
        assert_equal true, user.respond_to?(:data_yaml)
        assert_equal true, user.respond_to?(:data_json)
        assert_equal false, user.respond_to?(:encrypted_name)
        assert_equal true, user.respond_to?(:encrypted_bank_account_number_changed?)
        assert_equal true, user.respond_to?(:bank_account_number_changed?)
      end

      it "has unencrypted values" do
        assert_equal bank_account_number, user.bank_account_number
        assert_equal social_security_number, user.social_security_number
      end

      it "has encrypted values" do
        assert_equal bank_account_number_encrypted, user.encrypted_bank_account_number
        assert_equal social_security_number_encrypted, user.encrypted_social_security_number
      end

      describe ":random_iv" do
        it "false" do
          user.social_security_number = social_security_number
          assert first_value = user.social_security_number
          # Assign the same value
          user.social_security_number = social_security_number
          assert_equal first_value, user.social_security_number
        end

        it "true" do
          user.string_value = STRING_VALUE
          assert first_value = user.encrypted_string_value
          user.string_value = "blah"
          user.string_value = STRING_VALUE
          refute_equal first_value, user.encrypted_string_value
        end

        it "true and compress: true" do
          user.string_value      = STRING_VALUE
          user.long_string_value = STRING_VALUE

          refute_equal user.encrypted_long_string_value, user.encrypted_string_value
        end

        describe "changed?" do
          it "true for a new instance" do
            assert user.string_value_changed?
          end

          it "clears after save" do
            user.save!
            refute user.string_value_changed?
          end

          it "does not change when equal" do
            user.save!
            before            = user.encrypted_string_value
            user.string_value = STRING_VALUE
            refute user.string_value_changed?
            assert_equal before, user.encrypted_string_value
          end
        end
      end

      describe "attribute=" do
        it "handles nil" do
          user.string_value = nil
          assert_nil user.string_value
          assert_nil user.encrypted_string_value
          user.save!
          user.reload
          assert_nil user.string_value
          assert_nil user.encrypted_string_value
        end

        it "handles empty string" do
          user.string_value = ""
          assert_equal "", user.string_value
          assert_equal "", user.encrypted_string_value
          user.save!
          user.reload
          assert_equal "", user.string_value
          assert_equal "", user.encrypted_string_value
        end

        it "encrypt" do
          user                     = User.new
          user.bank_account_number = bank_account_number
          assert_equal bank_account_number, user.bank_account_number
          assert_equal bank_account_number_encrypted, user.encrypted_bank_account_number
        end

        it "all paths it lead to the same result" do
          assert_equal bank_account_number_encrypted, (user.encrypted_social_security_number = bank_account_number_encrypted)
          assert_equal bank_account_number, user.social_security_number
          assert_equal bank_account_number_encrypted, user.encrypted_social_security_number
        end

        it "all paths it lead to the same result 2" do
          assert_equal bank_account_number, (user.social_security_number = bank_account_number)
          assert_equal bank_account_number_encrypted, user.encrypted_social_security_number
          assert_equal bank_account_number, user.social_security_number
        end

        it "all paths it lead to the same result, check uninitialized" do
          user = User.new
          assert_nil user.social_security_number
          assert_equal bank_account_number, (user.social_security_number = bank_account_number)
          assert_equal bank_account_number, user.social_security_number
          assert_equal bank_account_number_encrypted, user.encrypted_social_security_number

          user.social_security_number = nil
          assert_nil user.social_security_number
          assert_nil user.encrypted_social_security_number
        end
      end

      describe ".new" do
        it "allows unencrypted values to be passed to the constructor" do
          user = User.new(bank_account_number: bank_account_number, social_security_number: social_security_number)
          assert_equal bank_account_number, user.bank_account_number
          assert_equal social_security_number, user.social_security_number
          assert_equal bank_account_number_encrypted, user.encrypted_bank_account_number
          assert_equal social_security_number_encrypted, user.encrypted_social_security_number
        end
      end

      describe ".encrypted_attributes" do
        it "returns encrypted attributes for the class" do
          expect = {social_security_number: :encrypted_social_security_number, bank_account_number: :encrypted_bank_account_number}
          result = User.encrypted_attributes
          expect.each_pair { |k, _v| assert_equal expect[k], result[k] }
        end
      end

      describe ".encrypted_keys" do
        it "return encrypted keys for the class" do
          expect = %i[social_security_number bank_account_number]
          result = User.encrypted_keys
          expect.each { |val| assert result.include?(val) }

          # Also check encrypted_attribute?
          expect.each { |val| assert User.encrypted_attribute?(val) }
        end
      end

      describe ".encrypted_columns" do
        it "return encrypted columns for the class" do
          expect = %i[encrypted_social_security_number encrypted_bank_account_number]
          result = User.encrypted_columns
          expect.each { |val| assert result.include?(val) }

          # Also check encrypted_column?
          expect.each { |val| assert User.encrypted_column?(val) }
        end
      end

      describe "#valid?" do
        before do
          assert user.valid?
        end

        it "fails invalid data" do
          user.encrypted_bank_account_number = "123"
          assert_equal false, user.valid?
          assert_equal ["must be a value encrypted using SymmetricEncryption.encrypt"], user.errors[:encrypted_bank_account_number]
        end

        it "passes encrypted data" do
          user.encrypted_bank_account_number = SymmetricEncryption.encrypt("123")
          assert user.valid?
        end

        it "passes valid data" do
          user.bank_account_number = "123"
          assert user.valid?
        end

        it "passes nil encrypted data" do
          user.encrypted_bank_account_number = nil
          assert user.valid?
        end

        it "passes empty string encrypted data" do
          user.encrypted_bank_account_number = ""
          assert user.valid?
        end

        it "passes nil data" do
          user.bank_account_number = nil
          assert user.valid?
        end

        it "passes empty string data" do
          user.bank_account_number = ""
          assert user.valid?
        end

        it "validate un-encrypted string data" do
          assert user.valid?
          user.text = "123"
          assert_equal false, user.valid?
          assert_equal ["only allows letters"], user.errors[:text]
          user.text = nil
          assert_equal false, user.valid?
          assert_equal ["only allows letters", "can't be blank"], user.errors[:text]
          user.text = ""
          assert_equal false, user.valid?
          assert_equal ["only allows letters", "can't be blank"], user.errors[:text]
        end

        it "validate un-encrypted integer data with coercion" do
          assert user.valid?
          user.number = "123"
          assert user.valid?
          assert_equal 123, user.number
          assert user.valid?
          user.number = ""
          assert_equal false, user.valid?
          assert_equal "", user.number
          assert_equal ["can't be blank"], user.errors[:number]
          user.number = nil
          assert_nil user.number
          assert_nil user.encrypted_number
          assert_equal false, user.valid?
          assert_equal ["can't be blank"], user.errors[:number]
        end
      end

      describe "with saved user" do
        before do
          user.save!
        end

        after do
          user&.destroy
        end

        it "return correct data type before save" do
          u = User.new(integer_value: "5")
          assert_equal 5, u.integer_value
          assert u.integer_value.is_a?(Integer)
        end

        it "handle gsub! for non-encrypted_field" do
          user.name.tr!("a", "v")
          new_name = person_name.tr("a", "v")
          assert_equal new_name, user.name
          user.reload
          assert_equal new_name, user.name
        end

        it "prevent gsub! on non-encrypted value of encrypted_field" do
          # can't modify frozen String
          assert_raises RuntimeError do
            user.bank_account_number.tr!("5", "4")
          end
        end

        describe "#reload" do
          it "reverts changes" do
            new_bank_account_number  = "444444444"
            user.bank_account_number = new_bank_account_number
            assert_equal new_bank_account_number, user.bank_account_number

            # Reload User model from the database
            user.reload
            assert_equal bank_account_number_encrypted, user.encrypted_bank_account_number
            assert_equal bank_account_number, user.bank_account_number
          end

          it "reverts changes to encrypted field" do
            new_bank_account_number            = "111111111"
            new_encrypted_bank_account_number  = SymmetricEncryption.encrypt(new_bank_account_number)
            user.encrypted_bank_account_number = new_encrypted_bank_account_number
            assert_equal new_encrypted_bank_account_number, user.encrypted_bank_account_number
            assert_equal new_bank_account_number, user.bank_account_number

            # Reload User model from the database
            user.reload
            assert_equal bank_account_number_encrypted, user.encrypted_bank_account_number
            assert_equal bank_account_number, user.bank_account_number
          end
        end

        describe "data types" do
          before do
            @user_clone = User.find(user.id)
          end

          [
            # @formatter:off
          {attribute: :integer_value,       klass: Integer,    value: INTEGER_VALUE,       new_value: 98},
          {attribute: :float_value,         klass: Float,      value: FLOAT_VALUE,         new_value: 45.4321},
          {attribute: :decimal_value,       klass: BigDecimal, value: DECIMAL_VALUE,       new_value: BigDecimal("99.95"), coercible: "22.51"},
          {attribute: :datetime_value,      klass: DateTime,   value: DATETIME_VALUE,      new_value: DateTime.new(1998, 10, 21, 8, 33, 28, "+5"), coercible: DATETIME_VALUE.to_time},
          {attribute: :time_value,          klass: Time,       value: TIME_VALUE,          new_value: Time.new(2000, 1, 1, 22, 30, 0, "-04:00")},
          {attribute: :date_value,          klass: Date,       value: DATE_VALUE,          new_value: Date.new(2027, 4, 2), coercible: DATE_VALUE.to_time},
          {attribute: :true_value,          klass: TrueClass,  value: true,                new_value: false},
          {attribute: :false_value,         klass: FalseClass, value: false,               new_value: true},
          {attribute: :string_value,        klass: String,     value: STRING_VALUE,        new_value: "Hello World"},
          {attribute: :long_string_value,   klass: String,     value: LONG_STRING_VALUE,   new_value: "A Really long Hello World"},
          {attribute: :binary_string_value, klass: String,     value: BINARY_STRING_VALUE, new_value: "A new Non-UTF8 Binary \x92 string".force_encoding("BINARY")}
          # @formatter:on
          ].each do |value_test|
            describe "#{value_test[:klass]} values" do
              before do
                @attribute = value_test[:attribute]
                @klass     = value_test[:klass]
                @value     = value_test[:value]
                @coercible = value_test[:coercible] || @value.to_s
                @new_value = value_test[:new_value]
              end

              it "return correct data type" do
                val = @user_clone.send(@attribute)
                # Need to dup since minitest attempts to modify the decrypted value which is frozen
                val = val.dup if val.duplicable?
                assert_equal @value, val, @user_clone.attributes.ai
                assert user.send(@attribute).is_a?(@klass)
              end

              it "coerce data type before save" do
                u = User.new(@attribute => @value)
                assert_equal @value, u.send(@attribute)
                assert u.send(@attribute).is_a?(@klass), "Value supposed to be coerced into #{@klass}, but is #{u.send(@attribute).class.name}"
              end

              it "permit replacing value with nil" do
                @user_clone.send("#{@attribute}=".to_sym, nil)
                @user_clone.save!

                user.reload
                assert_nil user.send(@attribute)
                assert_nil user.send("encrypted_#{@attribute}".to_sym)
              end

              it "permit replacing value with an empty string" do
                @user_clone.send("#{@attribute}=".to_sym, "")
                @user_clone.save!

                user.reload
                assert_equal "", user.send(@attribute)
                assert_equal "", user.send("encrypted_#{@attribute}".to_sym)
              end

              it "permit replacing value" do
                @user_clone.send("#{@attribute}=".to_sym, @new_value)
                @user_clone.save!

                user.reload
                val = user.send(@attribute)
                # Need to dup since minitest attempts to modify the decrypted value which is frozen
                val = val.dup if val.duplicable?
                assert_equal @new_value, val
              end
            end
          end

          describe "JSON Serialization" do
            let :hash_data do
              {"a" => "A", "b" => "B"}
            end

            it "return correct data type" do
              assert_equal hash_data, @user_clone.data_json
              assert user.clone.data_json.is_a?(Hash)
            end

            it "not coerce data type (leaves as hash) before save" do
              u = User.new(data_json: hash_data)
              assert_equal hash_data, u.data_json
              assert u.data_json.is_a?(Hash)
            end

            it "permit replacing value with nil" do
              @user_clone.data_json = nil
              @user_clone.save!

              user.reload
              assert_nil user.data_json
              assert_nil user.encrypted_data_json
            end

            it "permit replacing value" do
              new_value             = hash_data.clone
              new_value["c"]        = "C"
              @user_clone.data_json = new_value
              @user_clone.save!

              user.reload
              assert_equal new_value, user.data_json
            end
          end

          describe "YAML Serialization" do
            it "return correct data type" do
              assert_equal hash_data, @user_clone.data_yaml
              assert user.clone.data_yaml.is_a?(Hash)
            end

            it "not coerce data type (leaves as hash) before save" do
              u = User.new(data_yaml: hash_data)
              assert_equal hash_data, u.data_yaml
              assert u.data_yaml.is_a?(Hash)
            end

            it "permit replacing value with nil" do
              @user_clone.data_yaml = nil
              @user_clone.save!

              user.reload
              assert_nil user.data_yaml
              assert_nil user.encrypted_data_yaml
            end

            it "permit replacing value" do
              new_value             = hash_data.clone
              new_value[:c]         = "C"
              @user_clone.data_yaml = new_value
              @user_clone.save!

              user.reload
              assert_equal new_value, user.data_yaml
            end
          end
        end

        describe "changed?" do
          it "return false if it was not changed" do
            assert_equal false, user.encrypted_bank_account_number_changed?
            assert_equal false, user.bank_account_number_changed?
          end

          it "return true if it was changed" do
            user.bank_account_number = "15424623"
            assert user.encrypted_bank_account_number_changed?
            assert user.bank_account_number_changed?
          end
        end
      end

      describe "uniqueness" do
        before do
          UniqueUser.destroy_all
          @email    = "whatever@not-unique.com"
          @username = "gibby007"
          UniqueUser.create!(email: @email)
          @email_user = UniqueUser.create!(username: @username)
        end

        it "does not allow duplicate values" do
          duplicate = UniqueUser.new(email: @email)
          assert_equal false, duplicate.valid?
          assert_equal "has already been taken", duplicate.errors.messages[:encrypted_email].first
        end
      end
    end
  end
end
