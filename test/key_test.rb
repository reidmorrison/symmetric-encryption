require_relative 'test_helper'

class KeyTest < Minitest::Test
  describe SymmetricEncryption::Key do
    before do
      Dir.mkdir('tmp') unless Dir.exist?('tmp')
    end

    after do
      # Cleanup generated encryption key files.
      `rm tmp/dek_tester* 2> /dev/null`
    end

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

    let :stored_key2 do
      'ABCDEF1234567890ABCDEF1234567890'
    end

    let :stored_iv2 do
      '1234567890ABCDEF'
    end

    let :key2 do
      SymmetricEncryption::Key.new(key: stored_key2, iv: stored_iv2)
    end

    let :stored_key3 do
      'ABCDEF0123456789ABCDEF0123456789'
    end

    let :stored_iv3 do
      '0123456789ABCDEF'
    end

    let :key3 do
      SymmetricEncryption::Key.new(key: stored_key3, iv: stored_iv3)
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

    describe '.from_config' do
      let :config do
        {key: stored_key, iv: stored_iv}
      end

      let :config_key do
        SymmetricEncryption::Key.from_config(config)
      end

      let :dek_file_name do
        'tmp/dek_tester_dek.encrypted_key'
      end

      describe 'key' do
        it 'key' do
          assert_equal stored_key, config_key.key
        end

        it 'iv' do
          assert_equal stored_iv, config_key.iv
        end

        it 'cipher_name' do
          assert_equal 'aes-256-cbc', config_key.cipher_name
        end
      end

      describe 'encrypted_key' do
        let :config do
          {encrypted_key: key2.encrypt(stored_key), iv: stored_iv, key_encrypting_key: {key: stored_key2, iv: stored_iv2}}
        end

        it 'key' do
          assert_equal stored_key, config_key.key
        end

        it 'iv' do
          assert_equal stored_iv, config_key.iv
        end

        it 'cipher_name' do
          assert_equal 'aes-256-cbc', config_key.cipher_name
        end
      end

      describe 'key_filename' do
        let :config do
          File.open(dek_file_name, 'wb') { |f| f.write(key2.encrypt(stored_key)) }
          {key_filename: dek_file_name, iv: stored_iv, key_encrypting_key: {key: stored_key2, iv: stored_iv2}}
        end

        it 'key' do
          assert_equal stored_key, config_key.key
        end

        it 'iv' do
          assert_equal stored_iv, config_key.iv
        end

        it 'cipher_name' do
          assert_equal 'aes-256-cbc', config_key.cipher_name
        end
      end

      describe 'key_env_var' do
        let :env_var do
          'TEST_KEY'
        end

        let :config do
          ENV[env_var] = ::Base64.encode64(key2.encrypt(stored_key))
          {key_env_var: env_var, iv: stored_iv, key_encrypting_key: {key: stored_key2, iv: stored_iv2}}
        end

        it 'key' do
          assert_equal stored_key, config_key.key
        end

        it 'iv' do
          assert_equal stored_iv, config_key.iv
        end

        it 'cipher_name' do
          assert_equal 'aes-256-cbc', config_key.cipher_name
        end
      end

      describe 'file store with kekek' do
        let :kekek_file_name do
          'tmp/tester_kekek.key'
        end

        let :config do
          File.open(dek_file_name, 'wb') { |f| f.write(key2.encrypt(stored_key)) }
          encrypted_key = key3.encrypt(stored_key2)
          File.open(kekek_file_name, 'wb') { |f| f.write(stored_key3) }
          {
            key_filename:       dek_file_name,
            iv:                 stored_iv,
            key_encrypting_key: {
              encrypted_key:      encrypted_key,
              iv:                 stored_iv2,
              key_encrypting_key: {
                key_filename: kekek_file_name,
                iv:           stored_iv3
              }
            }
          }
        end

        it 'key' do
          assert_equal stored_key, config_key.key
        end

        it 'iv' do
          assert_equal stored_iv, config_key.iv
        end

        it 'cipher_name' do
          assert_equal 'aes-256-cbc', config_key.cipher_name
        end
      end

    end

  end
end
