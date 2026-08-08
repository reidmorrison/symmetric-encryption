require_relative "../test_helper"

ActiveRecord::Base.configurations = YAML.safe_load(ERB.new(File.read("test/config/database.yml")).result)
ActiveRecord::Base.establish_connection(:test)

ActiveRecord::Schema.define version: 0 do
  create_table :filtered_people, force: true do |t|
    t.string :name
    t.string :ssn
  end
end

class FilteredPerson < ActiveRecord::Base
  attribute :ssn, :encrypted
end

class AutoFilteredAttributesTest < Minitest::Test
  describe "SymmetricEncryption::ActiveRecord::AutoFilteredAttributes" do
    before do
      FilteredPerson.delete_all
    end

    let(:ssn) { "123456789" }

    let :filtered_person do
      FilteredPerson.create!(name: "Joe Bloggs", ssn: ssn)
    end

    describe "filter_attributes" do
      it "includes the encrypted attribute" do
        assert_includes FilteredPerson.filter_attributes, :ssn
      end

      it "leaves unencrypted attributes alone" do
        refute_includes FilteredPerson.filter_attributes, :name
      end

      it "does not filter when disabled" do
        klass = with_filtering(false) do
          Class.new(ActiveRecord::Base) do
            self.table_name = "filtered_people"
            attribute :ssn, :encrypted
          end
        end

        refute_includes klass.filter_attributes, :ssn
      end
    end

    describe "#inspect" do
      it "does not include the decrypted value" do
        refute_includes filtered_person.inspect, ssn
        assert_includes filtered_person.inspect, "ssn: [FILTERED]"
      end

      it "includes unencrypted values" do
        assert_includes filtered_person.inspect, "Joe Bloggs"
      end

      it "does not include the decrypted value after the record has been read back" do
        filtered_person

        refute_includes FilteredPerson.first.inspect, ssn
      end
    end

    describe "#attribute_for_inspect" do
      it "does not return the decrypted value" do
        assert_equal "[FILTERED]", filtered_person.attribute_for_inspect(:ssn)
      end
    end

    describe "reading the attribute" do
      it "still returns the decrypted value" do
        assert_equal ssn, filtered_person.ssn
      end
    end

    describe "Rails filter_parameters" do
      it "adds the attribute in model.attribute form" do
        with_rails_application do |application|
          # Named before the attribute is declared, since the parameter name comes from the model name.
          klass = Class.new(ActiveRecord::Base) do
            self.table_name = "filtered_people"

            def self.name
              "FilterParameterPerson"
            end
          end
          klass.attribute :ssn, :encrypted

          assert_includes application.config.filter_parameters, "filter_parameter_person.ssn"
        end
      end

      it "skips an anonymous model, which has no parameter name" do
        with_rails_application do |application|
          Class.new(ActiveRecord::Base) do
            self.table_name = "filtered_people"
            attribute :ssn, :encrypted
          end

          assert_empty application.config.filter_parameters
        end
      end
    end

    # `filter_encrypted_attributes` is global state that is read when the attribute is declared.
    def with_filtering(value)
      previous                                        = SymmetricEncryption.filter_encrypted_attributes?
      SymmetricEncryption.filter_encrypted_attributes = value
      yield
    ensure
      SymmetricEncryption.filter_encrypted_attributes = previous
    end

    # Rails is not a dependency of the test suite, so stand in for the parts of it that are read.
    # Removed again afterwards, so that the other tests run as they do without Rails.
    def with_rails_application
      application = Struct.new(:config).new(Struct.new(:filter_parameters).new([]))
      Object.const_set(:Rails, Module.new { define_singleton_method(:application) { application } })
      yield application
    ensure
      Object.send(:remove_const, :Rails)
    end
  end
end
