require_relative "../test_helper"

module SymmetricEncryption
  class MemoryTest < Minitest::Test
    describe SymmetricEncryption::Keystore::Memory do
      describe ".generate_data_key" do
        let :version do
          10
        end

        let :keystore_config do
          SymmetricEncryption::Keystore::Memory.generate_data_key(
            cipher_name: "aes-256-cbc",
            app_name:    "tester",
            environment: "test",
            version:     version
          )
        end

        it "increments the version" do
          assert_equal 11, keystore_config[:version]
        end

        describe "with 255 version" do
          let :version do
            255
          end

          it "handles version wrap" do
            assert_equal 1, keystore_config[:version]
          end
        end

        it "retains cipher_name" do
          assert_equal "aes-256-cbc", keystore_config[:cipher_name]
        end

        it "includes the iv of the data encrypting key" do
          assert keystore_config[:iv]
        end

        it "is readable by Keystore.read_key" do
          assert SymmetricEncryption::Keystore.read_key(**keystore_config)
        end

        it "secures the data key with the key encrypting key" do
          config = keystore_config
          kek    = SymmetricEncryption::Key.new(**config[:key_encrypting_key])

          refute_equal kek.key, config[:encrypted_key]
          assert_equal SymmetricEncryption::Keystore.read_key(**config).key, kek.decrypt(config[:encrypted_key])
        end

        describe "with a supplied data encrypting key" do
          let :dek do
            SymmetricEncryption::Key.new(cipher_name: "aes-128-cbc")
          end

          let :keystore_config do
            SymmetricEncryption::Keystore::Memory.generate_data_key(
              cipher_name: "aes-128-cbc",
              app_name:    "tester",
              environment: "test",
              version:     version,
              dek:         dek
            )
          end

          it "retains the supplied key" do
            assert_equal dek.key, SymmetricEncryption::Keystore.read_key(**keystore_config).key
          end

          it "retains the supplied iv" do
            assert_equal dek.iv, keystore_config[:iv]
          end
        end
      end

      describe "#write and #read" do
        let :key_encrypting_key do
          SymmetricEncryption::Key.new
        end

        let :keystore do
          SymmetricEncryption::Keystore::Memory.new(key_encrypting_key: key_encrypting_key)
        end

        it "round trips the key" do
          keystore.write("1234567890ABCDEF1234567890ABCDEF")

          assert_equal "1234567890ABCDEF1234567890ABCDEF", keystore.read
        end

        it "stores the key encrypted" do
          keystore.write("1234567890ABCDEF1234567890ABCDEF")

          refute_equal "1234567890ABCDEF1234567890ABCDEF", keystore.encrypted_key
        end

        it "reads a key supplied on creation" do
          encrypted = key_encrypting_key.encrypt("1234567890ABCDEF1234567890ABCDEF")
          keystore  = SymmetricEncryption::Keystore::Memory.new(
            key_encrypting_key: key_encrypting_key,
            encrypted_key:      encrypted
          )

          assert_equal "1234567890ABCDEF1234567890ABCDEF", keystore.read
        end
      end
    end
  end
end
