# Allow examples to be run in-place without requiring a gem install
$LOAD_PATH.unshift File.dirname(__FILE__) + '/../lib'

require 'rubygems'
require 'logger'
require 'erb'
require 'test/unit'
require 'shoulda'
# Since we want both the AR and Mongoid extensions loaded we need to require them first
require 'active_record'
require 'mongoid'
require 'symmetric-encryption'

ActiveRecord::Base.logger = Logger.new($stderr)
ActiveRecord::Base.configurations = YAML::load(ERB.new(IO.read('test/config/database.yml')).result)
ActiveRecord::Base.establish_connection('test')

ActiveRecord::Schema.define :version => 0 do
  create_table :users, :force => true do |t|
    t.string :encrypted_bank_account_number
    t.string :encrypted_social_security_number
    t.string :name
  end
end

class User < ActiveRecord::Base
  attr_encrypted :bank_account_number
  attr_encrypted :social_security_number

  validates :encrypted_bank_account_number, :symmetric_encryption => true
  validates :encrypted_social_security_number, :symmetric_encryption => true
end

# Load Symmetric Encryption keys
SymmetricEncryption.load!(File.join(File.dirname(__FILE__), 'config', 'symmetric-encryption.yml'), 'test')

# Initialize the database connection
config_file = File.join(File.dirname(__FILE__), 'config', 'database.yml')
raise "database config not found. Create a config file at: test/config/database.yml" unless File.exists? config_file

cfg = YAML.load(ERB.new(File.new(config_file).read).result)['test']
raise("Environment 'test' not defined in test/config/database.yml") unless cfg

User.establish_connection(cfg)

#
# Unit Test for attr_encrypted and validation aspects of SymmetricEncryption
#
class AttrEncryptedTest < Test::Unit::TestCase
  context 'the SymmetricEncryption Library' do

    setup do
      @bank_account_number = "1234567890"
      @bank_account_number_encrypted = "L94ArJeFlJrZp6SYsvoOGA=="

      @social_security_number = "987654321"
      @social_security_number_encrypted = "S+8X1NRrqdfEIQyFHVPuVA=="

      @user = User.new(
        # Encrypted Attribute
        :bank_account_number              => @bank_account_number,
        # Encrypted Attribute
        :social_security_number           => @social_security_number
      )
    end

    should "have encrypted methods" do
      assert_equal true, @user.respond_to?(:encrypted_bank_account_number)
      assert_equal true, @user.respond_to?(:bank_account_number)
      assert_equal true, @user.respond_to?(:encrypted_social_security_number)
      assert_equal true, @user.respond_to?(:social_security_number)
      assert_equal false, @user.respond_to?(:encrypted_name)
    end

    should "have unencrypted values" do
      assert_equal @bank_account_number, @user.bank_account_number
      assert_equal @social_security_number, @user.social_security_number
    end

    should "have encrypted values" do
      assert_equal @bank_account_number_encrypted, @user.encrypted_bank_account_number
      assert_equal @social_security_number_encrypted, @user.encrypted_social_security_number
    end

    should "encrypt" do
      user = User.new
      user.bank_account_number = @bank_account_number
      assert_equal @bank_account_number, user.bank_account_number
      assert_equal @bank_account_number_encrypted, user.encrypted_bank_account_number
    end

    should "allow lookups using unencrypted or encrypted column name" do
      @user.save!

      inq = User.find_by_bank_account_number(@bank_account_number)
      assert_equal @bank_account_number, inq.bank_account_number
      assert_equal @bank_account_number_encrypted, inq.encrypted_bank_account_number

      @user.delete
    end

    should "all paths should lead to the same result" do
      assert_equal @bank_account_number_encrypted, (@user.encrypted_social_security_number = @bank_account_number_encrypted)
      assert_equal @bank_account_number, @user.social_security_number
      assert_equal @bank_account_number_encrypted, @user.encrypted_social_security_number
    end

    should "all paths should lead to the same result 2" do
      assert_equal @bank_account_number, (@user.social_security_number = @bank_account_number)
      assert_equal @bank_account_number_encrypted, @user.encrypted_social_security_number
      assert_equal @bank_account_number, @user.social_security_number
    end

    should "all paths should lead to the same result, check uninitialized" do
      user = User.new
      assert_equal nil, user.social_security_number
      assert_equal @bank_account_number, (user.social_security_number = @bank_account_number)
      assert_equal @bank_account_number, user.social_security_number
      assert_equal @bank_account_number_encrypted, user.encrypted_social_security_number

      assert_equal nil, (user.social_security_number = nil)
      assert_equal nil, user.social_security_number
      assert_equal nil, user.encrypted_social_security_number
    end

    should "allow unencrypted values to be passed to the constructor" do
      user = User.new(:bank_account_number => @bank_account_number, :social_security_number => @social_security_number)
      assert_equal @bank_account_number, user.bank_account_number
      assert_equal @social_security_number, user.social_security_number
      assert_equal @bank_account_number_encrypted, user.encrypted_bank_account_number
      assert_equal @social_security_number_encrypted, user.encrypted_social_security_number
    end

    should "return encrypted attributes for the class" do
      expect = {:social_security_number=>:encrypted_social_security_number, :bank_account_number=>:encrypted_bank_account_number}
      result = User.encrypted_attributes
      expect.each_pair {|k,v| assert_equal expect[k], result[k]}
    end

    should "return encrypted keys for the class" do
      expect = [:social_security_number, :bank_account_number]
      result = User.encrypted_keys
      expect.each {|val| assert_equal true, result.include?(val)}

      # Also check encrypted_attribute?
      expect.each {|val| assert_equal true, User.encrypted_attribute?(val)}
    end

    should "return encrypted columns for the class" do
      expect = [:encrypted_social_security_number, :encrypted_bank_account_number]
      result = User.encrypted_columns
      expect.each {|val| assert_equal true, result.include?(val)}

      # Also check encrypted_column?
      expect.each {|val| assert_equal true, User.encrypted_column?(val)}
    end

    should "validate encrypted data" do
      assert_equal true, @user.valid?
      @user.encrypted_bank_account_number = '123'
      assert_equal false, @user.valid?
      assert_equal ["must be a value encrypted using SymmetricEncryption.encrypt"], @user.errors[:encrypted_bank_account_number]
      @user.encrypted_bank_account_number = SymmetricEncryption.encrypt('123')
      assert_equal true, @user.valid?
      @user.bank_account_number = '123'
      assert_equal true, @user.valid?
    end

  end

end