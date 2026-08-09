require_relative "test_helper"

# `with_cipher` uses a cipher that is not in `symmetric-encryption.yml` for the duration of a
# block, for data encrypted with a key of its own, such as a key per customer.
class WithCipherTest < Minitest::Test
  describe SymmetricEncryption do
    let :clear_value do
      "Hello World"
    end

    # Authenticated, because encrypting with a key that belongs to somebody else is the mistake
    # this makes possible, and an authenticated cipher is what turns it into a failure.
    let :the_cipher do
      SymmetricEncryption::Cipher.new(key: "1" * 32, cipher_name: "aes-256-gcm", version: 200)
    end

    # Another customer's cipher, deliberately sharing a version with the one above. Nothing stops
    # two keys held outside the configuration file from being given the same version.
    let :another_cipher do
      SymmetricEncryption::Cipher.new(key: "2" * 32, cipher_name: "aes-256-gcm", version: 200)
    end

    let :encrypted_in_scope do
      SymmetricEncryption.with_cipher(the_cipher) { SymmetricEncryption.encrypt(clear_value) }
    end

    let :encrypted_globally do
      SymmetricEncryption.encrypt(clear_value)
    end

    describe "inside the block" do
      it "encrypts with the supplied cipher" do
        SymmetricEncryption.with_cipher(the_cipher) do
          assert_equal the_cipher.version, SymmetricEncryption.header(encrypted_in_scope).version
        end
      end

      it "decrypts what it encrypted" do
        value = encrypted_in_scope

        SymmetricEncryption.with_cipher(the_cipher) do
          assert_equal clear_value, SymmetricEncryption.decrypt(value)
        end
      end

      # Data encrypted before the block's cipher existed still has to be readable, otherwise a
      # customer's own key would cut them off from everything else the application encrypted.
      it "still decrypts data encrypted with the configured ciphers" do
        value = encrypted_globally

        SymmetricEncryption.with_cipher(the_cipher) do
          assert_equal clear_value, SymmetricEncryption.decrypt(value)
        end
      end

      it "returns the supplied cipher from .cipher" do
        SymmetricEncryption.with_cipher(the_cipher) do
          assert_same the_cipher, SymmetricEncryption.cipher
        end
      end

      it "has a cipher" do
        SymmetricEncryption.with_cipher(the_cipher) do
          assert_predicate SymmetricEncryption, :cipher?
        end
      end
    end

    describe "outside the block" do
      it "puts the configured cipher back" do
        configured = SymmetricEncryption.cipher
        SymmetricEncryption.with_cipher(the_cipher) { nil }

        assert_same configured, SymmetricEncryption.cipher
      end

      it "puts the configured cipher back when the block raises" do
        configured = SymmetricEncryption.cipher
        assert_raises(RuntimeError) { SymmetricEncryption.with_cipher(the_cipher) { raise "boom" } }

        assert_same configured, SymmetricEncryption.cipher
      end

      it "returns the value of the block" do
        assert_equal :returned, SymmetricEncryption.with_cipher(the_cipher) { :returned }
      end

      # The cipher is not in the configuration file, so nothing outside the block knows the key.
      it "cannot decrypt what was encrypted inside the block" do
        value = encrypted_in_scope

        assert_raises SymmetricEncryption::CipherError do
          SymmetricEncryption.decrypt(value)
        end
      end
    end

    describe "nesting" do
      it "restores the outer cipher" do
        SymmetricEncryption.with_cipher(the_cipher) do
          SymmetricEncryption.with_cipher(another_cipher) do
            assert_same another_cipher, SymmetricEncryption.cipher
          end

          assert_same the_cipher, SymmetricEncryption.cipher
        end
      end
    end

    # Encrypting with a cipher that belongs to somebody else is the mistake this makes possible.
    describe "the wrong cipher" do
      it "does not decrypt another cipher's data" do
        value = encrypted_in_scope

        assert_raises(OpenSSL::Cipher::CipherError, SymmetricEncryption::CipherError) do
          SymmetricEncryption.with_cipher(another_cipher) { SymmetricEncryption.decrypt(value) }
        end
      end
    end

    describe "rotating a scoped key" do
      let :the_previous_cipher do
        SymmetricEncryption::Cipher.new(key: "3" * 32, cipher_name: "aes-256-gcm", version: 199)
      end

      let :encrypted_with_the_previous_cipher do
        SymmetricEncryption.with_cipher(the_previous_cipher) { SymmetricEncryption.encrypt(clear_value) }
      end

      it "reads data encrypted with the previous key" do
        value = encrypted_with_the_previous_cipher

        SymmetricEncryption.with_cipher(the_cipher, secondary_ciphers: [the_previous_cipher]) do
          assert_equal clear_value, SymmetricEncryption.decrypt(value)
        end
      end

      it "encrypts with the new key" do
        SymmetricEncryption.with_cipher(the_cipher, secondary_ciphers: [the_previous_cipher]) do
          encrypted = SymmetricEncryption.encrypt(clear_value)

          assert_equal the_cipher.version, SymmetricEncryption.header(encrypted).version
        end
      end
    end

    # Fiber storage rather than a thread variable, so that an Enumerator, which is a fiber, does
    # not silently drop back to the configured cipher part way through.
    describe "other fibers and threads" do
      it "is inherited by an enumerator" do
        SymmetricEncryption.with_cipher(the_cipher) do
          enumerator = Enumerator.new { |yielder| yielder << SymmetricEncryption.cipher }

          assert_same the_cipher, enumerator.first
        end
      end

      it "is inherited by a thread started inside the block" do
        SymmetricEncryption.with_cipher(the_cipher) do
          assert_same the_cipher, Thread.new { SymmetricEncryption.cipher }.value
        end
      end

      it "does not leak out of a thread started inside the block" do
        configured = SymmetricEncryption.cipher
        SymmetricEncryption.with_cipher(the_cipher) do
          Thread.new { SymmetricEncryption.with_cipher(another_cipher) { nil } }.join

          assert_same the_cipher, SymmetricEncryption.cipher
        end

        assert_same configured, SymmetricEncryption.cipher
      end
    end

    describe "arguments" do
      it "rejects something that is not a cipher" do
        assert_raises ArgumentError do
          SymmetricEncryption.with_cipher("not a cipher") { nil }
        end
      end

      it "rejects secondary ciphers that are not a collection" do
        assert_raises ArgumentError do
          SymmetricEncryption.with_cipher(the_cipher, secondary_ciphers: the_cipher) { nil }
        end
      end

      # The check happens before the scope is entered, so an outer scope is left alone.
      it "leaves the current cipher alone when the arguments are wrong" do
        SymmetricEncryption.with_cipher(the_cipher) do
          assert_raises(ArgumentError) { SymmetricEncryption.with_cipher(nil) { nil } }

          assert_same the_cipher, SymmetricEncryption.cipher
        end
      end
    end
  end
end
