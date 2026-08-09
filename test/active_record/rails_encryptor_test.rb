require_relative "../test_helper"

ActiveRecord::Base.configurations = YAML.safe_load(ERB.new(File.read("test/config/database.yml")).result)
ActiveRecord::Base.establish_connection(:test)

# Keys for Active Record encryption itself. Test values, they secure nothing.
ActiveRecord::Encryption.configure(
  primary_key:         "test" * 8,
  deterministic_key:   "determ" * 6,
  key_derivation_salt: "salt" * 8
)

ActiveRecord::Schema.define version: 0 do
  create_table :migrating_people, force: true do |t|
    t.string :ssn
    t.string :tag
  end
end

# A model part way through a migration from Symmetric Encryption to Active Record encryption.
class MigratingPerson < ActiveRecord::Base
  encrypts :ssn,
           previous: [{encryptor: SymmetricEncryption::ActiveRecord::RailsEncryptor.new}]

  # Active Record encrypts a deterministic attribute with the oldest scheme unless it is told
  # not to, and the encryptor below refuses to write.
  encrypts :tag,
           deterministic: {fixed: false},
           previous:      [{encryptor: SymmetricEncryption::ActiveRecord::RailsEncryptor.new}]
end

class RailsEncryptorTest < Minitest::Test
  describe SymmetricEncryption::ActiveRecord::RailsEncryptor do
    let :ssn do
      "123-45-6789"
    end

    # A row that predates the migration, written by Symmetric Encryption. Inserted below Active
    # Record encryption so that it is stored exactly as this gem left it.
    let :legacy_person do
      person = MigratingPerson.create!
      MigratingPerson.connection.execute(
        "UPDATE migrating_people SET ssn = #{quote(SymmetricEncryption.encrypt(ssn))}, " \
        "tag = #{quote(SymmetricEncryption.encrypt('legacy'))} WHERE id = #{person.id}"
      )
      MigratingPerson.find(person.id)
    end

    def quote(value)
      MigratingPerson.connection.quote(value)
    end

    def raw_value(person, column)
      MigratingPerson.connection.select_value("SELECT #{column} FROM migrating_people WHERE id = #{person.id}")
    end

    describe "#decrypt" do
      it "reads a value encrypted by symmetric encryption" do
        assert_equal ssn, legacy_person.ssn
      end

      it "reads a deterministic value encrypted by symmetric encryption" do
        assert_equal "legacy", legacy_person.tag
      end

      it "reads a value encrypted by active record encryption" do
        person = MigratingPerson.create!(ssn: ssn)

        assert_equal ssn, MigratingPerson.find(person.id).ssn
      end

      it "raises an active record error so that the previous schemes are tried" do
        error = assert_raises ActiveRecord::Encryption::Errors::Decryption do
          SymmetricEncryption::ActiveRecord::RailsEncryptor.new.decrypt("not encrypted at all")
        end

        refute_empty error.message
      end
    end

    describe "saving a record" do
      it "rewrites the value in the active record format" do
        person = legacy_person

        assert SymmetricEncryption.encrypted?(raw_value(person, "ssn"))

        person.ssn = "987-65-4321"
        person.save!

        refute SymmetricEncryption.encrypted?(raw_value(person, "ssn"))
        assert_equal "987-65-4321", MigratingPerson.find(person.id).ssn
      end

      it "leaves a value that was not written alone" do
        person = legacy_person
        person.tag = "rewritten"
        person.save!

        assert SymmetricEncryption.encrypted?(raw_value(person, "ssn"))
        assert_equal ssn, MigratingPerson.find(person.id).ssn
      end
    end

    describe "#encrypt" do
      # Writing is Active Record encryption's job once the migration has started, so that data
      # cannot silently go back to the old format.
      it "refuses to encrypt" do
        error = assert_raises ActiveRecord::Encryption::Errors::Encryption do
          SymmetricEncryption::ActiveRecord::RailsEncryptor.new.encrypt("Hello World")
        end

        assert_includes error.message, "only decrypts"
      end
    end

    describe "#encrypted?" do
      it "recognizes a symmetric encryption value" do
        assert SymmetricEncryption::ActiveRecord::RailsEncryptor.new.encrypted?(SymmetricEncryption.encrypt(ssn))
      end

      it "does not recognize an unencrypted value" do
        refute SymmetricEncryption::ActiveRecord::RailsEncryptor.new.encrypted?(ssn)
      end
    end

    describe "#binary?" do
      it "returns text" do
        refute_predicate SymmetricEncryption::ActiveRecord::RailsEncryptor.new, :binary?
      end
    end
  end
end
