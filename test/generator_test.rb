require_relative "test_helper"

module SymmetricEncryption
  class GeneratorTest < Minitest::Test
    describe SymmetricEncryption::Generator do
      # Stands in for an ActiveRecord or Mongoid model.
      let :model do
        Class.new do
          attr_accessor :encrypted_ssn, :encrypted_age

          def encrypted_ssn_changed?
            true
          end
        end
      end

      let :record do
        model.new
      end

      def generate(decrypted_name = :ssn, encrypted_name = :encrypted_ssn, options = {})
        SymmetricEncryption::Generator.generate_decrypted_accessors(model, decrypted_name, encrypted_name, options)
      end

      describe ".generate_decrypted_accessors" do
        it "encrypts on assignment" do
          generate

          record.ssn = "123456789"

          refute_equal "123456789", record.encrypted_ssn
          assert_equal "123456789", SymmetricEncryption.decrypt(record.encrypted_ssn)
        end

        it "decrypts on read" do
          generate

          record.encrypted_ssn = SymmetricEncryption.encrypt("123456789")

          assert_equal "123456789", record.ssn
        end

        it "re-decrypts when the encrypted value changes" do
          generate

          record.ssn = "123456789"
          assert_equal "123456789", record.ssn

          record.encrypted_ssn = SymmetricEncryption.encrypt("987654321")
          assert_equal "987654321", record.ssn
        end

        it "freezes the decrypted value" do
          generate

          record.ssn = +"123456789"

          assert record.ssn.frozen?
        end

        it "returns nil when the encrypted value is nil" do
          generate

          assert_nil record.ssn
        end

        it "delegates changed? to the encrypted attribute" do
          generate

          assert record.ssn_changed?
        end

        it "coerces the supplied type" do
          generate(:age, :encrypted_age, type: :integer)

          record.age = 21

          assert_equal 21, record.age
          assert_equal 21, SymmetricEncryption.decrypt(record.encrypted_age, type: :integer)
        end

        it "supports a random iv" do
          generate(:ssn, :encrypted_ssn, random_iv: true)

          record.ssn = "123456789"
          first      = record.encrypted_ssn

          other      = model.new
          other.ssn  = "123456789"

          refute_equal first, other.encrypted_ssn
          assert_equal "123456789", other.ssn
        end

        it "supports compression" do
          generate(:ssn, :encrypted_ssn, random_iv: true, compress: true)

          record.ssn = "123456789" * 100

          assert_equal "123456789" * 100, record.ssn
          assert SymmetricEncryption.header(record.encrypted_ssn).compressed?
        end

        it "adds both attributes to a single module" do
          generate
          generate(:age, :encrypted_age, type: :integer)

          assert model.const_defined?(:EncryptedAttributes, false)
          assert_equal(1, model.ancestors.count { |a| a.to_s.include?("EncryptedAttributes") })
        end

        it "raises when an option is not supported" do
          error = assert_raises(ArgumentError) { generate(:ssn, :encrypted_ssn, bad_option: true) }

          assert_includes error.message, "Invalid options"
        end

        it "raises when the type is not supported" do
          error = assert_raises(ArgumentError) { generate(:ssn, :encrypted_ssn, type: :bad_type) }

          assert_includes error.message, "Invalid type"
        end

        it "does not modify the supplied options" do
          options = {random_iv: true, compress: true, type: :string}

          generate(:ssn, :encrypted_ssn, options)

          assert_equal({random_iv: true, compress: true, type: :string}, options)
        end
      end
    end
  end
end
