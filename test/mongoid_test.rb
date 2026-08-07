require_relative "test_helper"

begin
  require "mongoid"
  require "symmetric_encryption/railties/mongoid_encrypted"
  ENV["RACK_ENV"] = "test"

  Mongoid.load!("test/config/mongoid.yml")

  # These tests need a running MongoDB, so verify up front that it is reachable.
  Mongoid.default_client.with(server_selection_timeout: 2).command(ping: 1)

  # @formatter:off
  class MongoidUser
    include Mongoid::Document

    field :name,                             type: String
    field :encrypted_bank_account_number,    type: String, encrypted: true
    field :encrypted_social_security_number, type: String, encrypted: true
    field :encrypted_string,                 type: String, encrypted: {random_iv: true}
    field :encrypted_long_string,            type: String, encrypted: {random_iv: true, compress: true}

    field :encrypted_integer_value,          type: String, encrypted: {type: :integer}
    field :aiv,                              type: String, encrypted: {type: :integer, decrypt_as: :aliased_integer_value}
    field :encrypted_float_value,            type: String, encrypted: {type: :float}
    field :encrypted_decimal_value,          type: String, encrypted: {type: :decimal}
    field :encrypted_datetime_value,         type: String, encrypted: {type: :datetime}
    field :encrypted_time_value,             type: String, encrypted: {type: :time}
    field :encrypted_date_value,             type: String, encrypted: {type: :date}
    field :encrypted_true_value,             type: String, encrypted: {type: :boolean}
    field :encrypted_false_value,            type: String, encrypted: {type: :boolean}
    field :encrypted_data_yaml,              type: String, encrypted: {random_iv: true, compress: true, type: :yaml}
    field :encrypted_data_json,              type: String, encrypted: {random_iv: true, compress: true, type: :json}

    validates :encrypted_bank_account_number,    symmetric_encryption: true
    validates :encrypted_social_security_number, symmetric_encryption: true
  end

  class MongoidUniqueUser
    include Mongoid::Document

    field :encrypted_email,    type: String, encrypted: true
    field :encrypted_username, type: String, encrypted: true

    validates_uniqueness_of :encrypted_email,    allow_blank: true, if: :encrypted_email_changed?
    validates_uniqueness_of :encrypted_username, allow_blank: true, if: :encrypted_username_changed?

    validates :username,
              length:      {in: 3..20},
              format:      {with: /\A[\w-]+\z/},
              allow_blank: true
  end
  # @formatter:on

  #
  # Unit Tests for field encrypted and validation aspects of SymmetricEncryption
  #
  class MongoidTest < Minitest::Test
    describe "Mongoid" do
      before do
        @bank_account_number           = "1234567890"
        @bank_account_number_encrypted = "QEVuQwIAL94ArJeFlJrZp6SYsvoOGA=="

        @social_security_number           = "987654321"
        @social_security_number_encrypted = "QEVuQwIAS+8X1NRrqdfEIQyFHVPuVA=="

        @integer           = 32_768
        @integer_encrypted = "FA3smFQEKqB/ITv+A0xACg=="

        @float           = 0.9867
        @float_encrypted = "z7Pwt2JDp74d+u0IXFAdrQ=="

        @date           = Date.parse("20120320")
        @date_encrypted = "WTkSPHo5ApSSHBJMxxWt2A=="

        @string      = "A string containing some data to be encrypted with a random initialization vector"
        @long_string = "A string containing some data to be encrypted with a random initialization vector and compressed since it takes up so much space in plain text form"

        @integer_value  = 12
        @float_value    = 88.12345
        @decimal_value  = BigDecimal("22.51")
        @datetime_value = DateTime.new(2001, 11, 26, 20, 55, 54, "-5")
        @time_value     = Time.new(2013, 0o1, 0o1, 22, 30, 0o0, "-04:00")
        @date_value     = Date.new(1927, 0o4, 0o2)
        @h              = {a: "A", b: "B"}

        @user = MongoidUser.new(
          encrypted_bank_account_number:    @bank_account_number_encrypted,
          encrypted_social_security_number: @social_security_number_encrypted,
          name:                             "Joe Bloggs",
          # data type specific fields
          integer_value:                    @integer_value,
          aliased_integer_value:            @integer_value,
          float_value:                      @float_value,
          decimal_value:                    @decimal_value,
          datetime_value:                   @datetime_value,
          time_value:                       @time_value,
          date_value:                       @date_value,
          true_value:                       true,
          false_value:                      false,
          data_yaml:                        @h.dup,
          data_json:                        @h.dup
        )
      end

      it "have encrypted methods" do
        assert_respond_to @user, :encrypted_bank_account_number
        assert_respond_to @user, :encrypted_social_security_number
        assert_respond_to @user, :encrypted_string
        assert_respond_to @user, :encrypted_long_string
        refute_respond_to @user, :encrypted_name

        assert_respond_to @user, :encrypted_bank_account_number=
        assert_respond_to @user, :encrypted_social_security_number=
        assert_respond_to @user, :encrypted_string=
        assert_respond_to @user, :encrypted_long_string=
        refute_respond_to @user, :encrypted_name=
      end

      it "have unencrypted methods" do
        assert_respond_to @user, :bank_account_number
        assert_respond_to @user, :social_security_number
        assert_respond_to @user, :string
        assert_respond_to @user, :long_string
        assert_respond_to @user, :name

        assert_respond_to @user, :bank_account_number=
        assert_respond_to @user, :social_security_number=
        assert_respond_to @user, :string=
        assert_respond_to @user, :long_string=
        assert_respond_to @user, :name=
      end

      it "support aliased fields" do
        assert_respond_to @user, :aliased_integer_value=
        assert_respond_to @user, :aliased_integer_value
      end

      it "have unencrypted values" do
        assert_equal @bank_account_number, @user.bank_account_number
        assert_equal @social_security_number, @user.social_security_number
      end

      it "have encrypted values" do
        assert_equal @bank_account_number_encrypted, @user.encrypted_bank_account_number
        assert_equal @social_security_number_encrypted, @user.encrypted_social_security_number
      end

      it "support same iv" do
        @user.social_security_number = @social_security_number

        assert first_value = @user.social_security_number
        # Assign the same value
        @user.social_security_number = @social_security_number

        assert_equal first_value, @user.social_security_number
      end

      it "support a random iv" do
        @user.string = @string

        assert first_value = @user.encrypted_string
        @user.string = "blah"
        @user.string = @string.dup

        refute_equal first_value, @user.encrypted_string
      end

      it "support a random iv and compress" do
        @user.string      = @long_string
        @user.long_string = @long_string

        assert_operator (@user.encrypted_long_string.length.to_f / @user.encrypted_string.length), :<, 0.8
      end

      it "encrypt" do
        user                     = MongoidUser.new
        user.bank_account_number = @bank_account_number

        assert_equal @bank_account_number, user.bank_account_number
        assert_equal @bank_account_number_encrypted, user.encrypted_bank_account_number
      end

      it "all paths it lead to the same result" do
        assert_equal @bank_account_number_encrypted, (@user.encrypted_social_security_number = @bank_account_number_encrypted)
        assert_equal @bank_account_number, @user.social_security_number
      end

      it "all paths it lead to the same result 2" do
        assert_equal @bank_account_number, (@user.social_security_number = @bank_account_number)
        assert_equal @bank_account_number_encrypted, @user.encrypted_social_security_number
      end

      it "all paths it lead to the same result, check uninitialized" do
        user = MongoidUser.new

        assert_nil user.social_security_number
        assert_equal @bank_account_number, (user.social_security_number = @bank_account_number)
        assert_equal @bank_account_number, user.social_security_number
        assert_equal @bank_account_number_encrypted, user.encrypted_social_security_number

        user.social_security_number = nil

        assert_nil user.social_security_number
        assert_nil user.encrypted_social_security_number
      end

      it "allow unencrypted values to be passed to the constructor" do
        user = MongoidUser.new(bank_account_number: @bank_account_number, social_security_number: @social_security_number)

        assert_equal @bank_account_number, user.bank_account_number
        assert_equal @social_security_number, user.social_security_number
        assert_equal @bank_account_number_encrypted, user.encrypted_bank_account_number
        assert_equal @social_security_number_encrypted, user.encrypted_social_security_number
      end

      it "allow both encrypted and unencrypted values to be passed to the constructor" do
        user = MongoidUser.new(encrypted_bank_account_number: @bank_account_number_encrypted, social_security_number: @social_security_number)

        assert_equal @bank_account_number, user.bank_account_number
        assert_equal @social_security_number, user.social_security_number
        assert_equal @bank_account_number_encrypted, user.encrypted_bank_account_number
        assert_equal @social_security_number_encrypted, user.encrypted_social_security_number
      end

      describe "changed?" do
        before do
          @user.save!
        end

        after do
          @user&.destroy
        end

        it "return false if it was not changed" do
          refute_predicate @user, :encrypted_bank_account_number_changed?
          refute_predicate @user, :bank_account_number_changed?
        end

        it "return true if it was changed" do
          @user.bank_account_number = "15424623"

          assert_predicate @user, :encrypted_bank_account_number_changed?
          assert_predicate @user, :bank_account_number_changed?
        end
      end

      describe "data types" do
        before do
          @user.save!
          @user_clone = MongoidUser.find(@user.id)
        end

        after do
          @user&.destroy
        end

        describe "aliased fields" do
          it "return correct data type" do
            @user_clone.aliased_integer_value = "5"

            assert_equal 5, @user_clone.aliased_integer_value
          end
        end

        describe "integer values" do
          it "return correct data type" do
            assert_equal @integer_value, @user_clone.integer_value
            assert_kind_of Integer, @user.clone.integer_value
          end

          it "coerce data type before save" do
            u = MongoidUser.new(integer_value: "5")

            assert_equal 5, u.integer_value
            assert_kind_of Integer, u.integer_value
          end

          it "permit replacing value with nil" do
            @user_clone.integer_value = nil
            @user_clone.save!

            @user.reload

            assert_nil @user.integer_value
            assert_nil @user.encrypted_integer_value
          end

          it "permit replacing value" do
            new_integer_value         = 98
            @user_clone.integer_value = new_integer_value
            @user_clone.save!

            @user.reload

            assert_equal new_integer_value, @user.integer_value
          end
        end

        describe "float values" do
          it "return correct data type" do
            assert_equal @float_value, @user_clone.float_value
            assert_kind_of Float, @user.clone.float_value
          end

          it "coerce data type before save" do
            u = MongoidUser.new(float_value: "5.6")

            assert_in_delta(5.6, u.float_value)
            assert_kind_of Float, u.float_value
          end

          it "permit replacing value with nil" do
            @user_clone.float_value = nil
            @user_clone.save!

            @user.reload

            assert_nil @user.float_value
            assert_nil @user.encrypted_float_value
          end

          it "permit replacing value" do
            new_float_value         = 45.4321
            @user_clone.float_value = new_float_value
            @user_clone.save!

            @user.reload

            assert_equal new_float_value, @user.float_value
          end
        end

        describe "decimal values" do
          it "return correct data type" do
            assert_equal @decimal_value, @user_clone.decimal_value
            assert_kind_of BigDecimal, @user.clone.decimal_value
          end

          it "coerce data type before save" do
            u = MongoidUser.new(decimal_value: "99.95")

            assert_equal BigDecimal("99.95"), u.decimal_value
            assert_kind_of BigDecimal, u.decimal_value
          end

          it "permit replacing value with nil" do
            @user_clone.decimal_value = nil
            @user_clone.save!

            @user.reload

            assert_nil @user.decimal_value
            assert_nil @user.encrypted_decimal_value
          end

          it "permit replacing value" do
            new_decimal_value         = BigDecimal("99.95")
            @user_clone.decimal_value = new_decimal_value
            @user_clone.save!

            @user.reload

            assert_equal new_decimal_value, @user.decimal_value
          end
        end

        describe "datetime values" do
          it "return correct data type" do
            assert_equal @datetime_value, @user_clone.datetime_value
            assert_kind_of DateTime, @user.clone.datetime_value
          end

          it "coerce data type before save" do
            now = Time.now
            u   = MongoidUser.new(datetime_value: now)

            assert_equal now, u.datetime_value
            assert_kind_of DateTime, u.datetime_value
          end

          it "permit replacing value with nil" do
            @user_clone.datetime_value = nil
            @user_clone.save!

            @user.reload

            assert_nil @user.datetime_value
            assert_nil @user.encrypted_datetime_value
          end

          it "permit replacing value" do
            new_datetime_value         = DateTime.new(1998, 10, 21, 8, 33, 28, "+5")
            @user_clone.datetime_value = new_datetime_value
            @user_clone.save!

            @user.reload

            assert_equal new_datetime_value, @user.datetime_value
          end
        end

        describe "time values" do
          it "return correct data type" do
            assert_equal @time_value, @user_clone.time_value.dup
            assert_kind_of Time, @user.clone.time_value
          end

          it "coerce data type before save" do
            now = Time.now
            u   = MongoidUser.new(time_value: now)

            assert_equal now, u.time_value.dup
            assert_kind_of Time, u.time_value
          end

          it "permit replacing value with nil" do
            @user_clone.time_value = nil
            @user_clone.save!

            @user.reload

            assert_nil @user.time_value
            assert_nil @user.encrypted_time_value
          end

          it "permit replacing value" do
            new_time_value         = Time.new(1998, 10, 21, 8, 33, 28, "+04:00")
            @user_clone.time_value = new_time_value
            @user_clone.save!

            @user.reload

            assert_equal new_time_value, @user.time_value.dup
          end
        end

        describe "date values" do
          it "return correct data type" do
            assert_equal @date_value, @user_clone.date_value
            assert_kind_of Date, @user.clone.date_value
          end

          it "coerce data type before save" do
            now = Time.now
            u   = MongoidUser.new(date_value: now)

            assert_equal now.to_date, u.date_value
            assert_kind_of Date, u.date_value
          end

          it "permit replacing value with nil" do
            @user_clone.date_value = nil
            @user_clone.save!

            @user.reload

            assert_nil @user.date_value
            assert_nil @user.encrypted_date_value
          end

          it "permit replacing value" do
            new_date_value         = Date.new(1998, 10, 21)
            @user_clone.date_value = new_date_value
            @user_clone.save!

            @user.reload

            assert_equal new_date_value, @user.date_value
          end
        end

        describe "true values" do
          it "return correct data type" do
            assert_equal true, @user_clone.true_value # rubocop:disable Minitest/AssertTruthy
            assert_kind_of TrueClass, @user.clone.true_value
          end

          it "coerce data type before save" do
            u = MongoidUser.new(true_value: "1")

            assert_equal true, u.true_value # rubocop:disable Minitest/AssertTruthy
            assert_kind_of TrueClass, u.true_value
          end

          it "permit replacing value with nil" do
            @user_clone.true_value = nil
            @user_clone.save!

            @user.reload

            assert_nil @user.true_value
            assert_nil @user.encrypted_true_value
          end

          it "permit replacing value" do
            new_value              = false
            @user_clone.true_value = new_value
            @user_clone.save!

            @user.reload

            assert_equal new_value, @user.true_value
          end
        end

        describe "false values" do
          it "return correct data type" do
            assert_equal false, @user_clone.false_value # rubocop:disable Minitest/RefuteFalse
            assert_kind_of FalseClass, @user.clone.false_value
          end

          it "coerce data type before save" do
            u = MongoidUser.new(false_value: "0")

            assert_equal false, u.false_value # rubocop:disable Minitest/RefuteFalse
            assert_kind_of FalseClass, u.false_value
          end

          it "permit replacing value with nil" do
            @user_clone.false_value = nil
            @user_clone.save!

            @user.reload

            assert_nil @user.false_value
            assert_nil @user.encrypted_false_value
          end

          it "permit replacing value" do
            new_value               = true
            @user_clone.false_value = new_value
            @user_clone.save!

            @user.reload

            assert_equal new_value, @user.false_value
          end
        end

        describe "JSON Serialization" do
          before do
            # JSON Does not support symbols, so they will come back as strings
            # Convert symbols to string in the test
            @h = @h.transform_keys(&:to_s)
          end

          it "return correct data type" do
            assert_equal @h, @user_clone.data_json
            assert_kind_of Hash, @user.clone.data_json
          end

          it "not coerce data type (leaves as hash) before save" do
            u = MongoidUser.new(data_json: @h)

            assert_equal @h, u.data_json
            assert_kind_of Hash, u.data_json
          end

          it "permit replacing value with nil" do
            @user_clone.data_json = nil
            @user_clone.save!

            @user.reload

            assert_nil @user.data_json
            assert_nil @user.encrypted_data_json
          end

          it "permit replacing value" do
            new_value             = @h.clone
            new_value["c"]        = "C"
            @user_clone.data_json = new_value
            @user_clone.save!

            @user.reload

            assert_equal new_value, @user.data_json
          end
        end

        describe "YAML Serialization" do
          it "return correct data type" do
            assert_equal @h, @user_clone.data_yaml
            assert_kind_of Hash, @user.clone.data_yaml
          end

          it "not coerce data type (leaves as hash) before save" do
            u = MongoidUser.new(data_yaml: @h)

            assert_equal @h, u.data_yaml
            assert_kind_of Hash, u.data_yaml
          end

          it "permit replacing value with nil" do
            @user_clone.data_yaml = nil
            @user_clone.save!

            @user.reload

            assert_nil @user.data_yaml
            assert_nil @user.encrypted_data_yaml
          end

          it "permit replacing value" do
            new_value             = @h.clone
            new_value[:c]         = "C"
            @user_clone.data_yaml = new_value
            @user_clone.save!

            @user.reload

            assert_equal new_value, @user.data_yaml
          end
        end
      end

      describe "uniqueness" do
        before do
          MongoidUniqueUser.destroy_all
          @email      = "whatever@not-unique.com"
          @username   = "gibby007"
          @user       = MongoidUniqueUser.create!(email: @email)
          @email_user = MongoidUniqueUser.create!(username: @username)
        end

        it "does not allow duplicate values" do
          duplicate = MongoidUniqueUser.new(email: @email)

          refute_predicate duplicate, :valid?
          assert_equal "has already been taken", duplicate.errors.messages[:encrypted_email].first
        end
      end
    end
  end
rescue LoadError
  puts "Not running Mongoid tests because the mongoid gem is not installed."
rescue Mongo::Error => e
  puts "Not running Mongoid tests because MongoDB is not available (#{e.class.name}). Start it with: docker compose up -d"
end
