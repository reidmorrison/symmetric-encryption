require_relative "../test_helper"

ActiveRecord::Base.configurations = YAML.safe_load(ERB.new(File.read("test/config/database.yml")).result)
ActiveRecord::Base.establish_connection(:test)

ActiveRecord::Schema.define version: 0 do
  create_table :json_people, force: true do |t|
    t.string :name
    t.string :ssn
    t.string :age
  end
end

class JsonPerson < ActiveRecord::Base
  include SymmetricEncryption::ActiveRecord::ExcludeFromJson

  attribute :ssn, :encrypted
  attribute :age, :encrypted, type: :integer
end

# Without the module the decrypted values are rendered, which is the Active Record default.
class UnfilteredJsonPerson < ActiveRecord::Base
  self.table_name = "json_people"

  attribute :ssn, :encrypted
end

class ExcludeFromJsonTest < Minitest::Test
  describe "SymmetricEncryption::ActiveRecord::ExcludeFromJson" do
    before do
      JsonPerson.delete_all
    end

    let(:ssn) { "123456789" }

    let :json_person do
      JsonPerson.create!(name: "Joe Bloggs", ssn: ssn, age: 42)
    end

    describe "#as_json" do
      it "excludes every encrypted attribute" do
        assert_equal({"id" => json_person.id, "name" => "Joe Bloggs"}, json_person.as_json)
      end

      it "excludes them from a record read back from the database" do
        json_person

        assert_equal({"id" => json_person.id, "name" => "Joe Bloggs"}, JsonPerson.first.as_json)
      end

      it "honors :except for unencrypted attributes" do
        assert_equal({"id" => json_person.id}, json_person.as_json(except: :name))
      end

      it "excludes them even when :only asks for them" do
        assert_equal({"name" => "Joe Bloggs"}, json_person.as_json(only: %i[name ssn age]))
      end

      it "returns nothing when :only asks for encrypted attributes alone" do
        assert_empty json_person.as_json(only: %i[ssn age])
      end

      it "includes requested methods" do
        assert_equal({"id" => json_person.id, "name" => "Joe Bloggs", "ssn" => ssn},
                     json_person.as_json(methods: :ssn))
      end
    end

    describe "#to_json" do
      it "does not include the decrypted value" do
        refute_includes json_person.to_json, ssn
      end
    end

    describe "#serializable_hash" do
      it "excludes every encrypted attribute" do
        assert_equal({"id" => json_person.id, "name" => "Joe Bloggs"}, json_person.serializable_hash)
      end
    end

    describe "the model itself" do
      it "still returns the decrypted values" do
        assert_equal ssn, json_person.ssn
        assert_equal 42, json_person.age
      end

      it "still includes them in #attributes" do
        assert_equal ssn, json_person.attributes["ssn"]
      end
    end

    describe "a model without the module" do
      it "renders the decrypted value, as Active Record does" do
        person = UnfilteredJsonPerson.create!(name: "Joe Bloggs", ssn: ssn)

        assert_equal ssn, person.as_json["ssn"]
      end
    end
  end
end
