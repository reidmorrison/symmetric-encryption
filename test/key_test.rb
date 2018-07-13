require_relative 'test_helper'

class KeyTest < Minitest::Test
  describe SymmetricEncryption::Key do
    let :random_key do
      SymmetricEncryption::Key.new
    end

    let :stored_key do
      '1234567890ABCDEF1234567890ABCDEF'
    end

    let :stored_iv do
      'ABCDEF1234567890'
    end

    let :key do
      SymmetricEncryption::Key.new(key: stored_key, iv: stored_iv)
    end

    let :ssn do
      '987654321'
    end

    let :encrypted_ssn do
      essn = "cR\x9C,\x91\xA4{\b`\x9Fls\xA4\f\xD1\xBF"
      essn.force_encoding('binary')
      essn
    end

    describe 'encrypt' do
      it 'empty string' do
        assert_equal '', key.encrypt('')
      end

      it 'nil' do
        assert_nil key.encrypt(nil)
      end

      it 'string' do
        assert_equal encrypted_ssn, key.encrypt(ssn)
      end
    end

    describe 'decrypt' do
      it 'empty string' do
        assert_equal '', key.decrypt('')
      end

      it 'nil' do
        assert_nil key.decrypt(nil)
      end

      it 'string' do
        assert_equal ssn, key.decrypt(encrypted_ssn)
      end
    end

    describe 'key' do
      it 'creates random key by default' do
        assert key = random_key.key
        refute_equal key, SymmetricEncryption::Key.new.key
      end

      it 'stores' do
        assert_equal stored_key, key.key
      end
    end

    describe 'iv' do
      it 'creates random iv by default' do
        assert iv = random_key.iv
        refute_equal iv, SymmetricEncryption::Key.new.iv
      end

      it 'stores' do
        assert_equal stored_iv, key.iv
      end
    end
  end
end
