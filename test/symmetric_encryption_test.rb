require_relative 'test_helper'

# Unit Test for SymmetricEncryption
#
class SymmetricEncryptionTest < Minitest::Test
  describe 'SymmetricEncryption' do

    describe 'configuration' do
      before do
        config                             = SymmetricEncryption::Config.read_config(File.join(File.dirname(__FILE__), 'config', 'symmetric-encryption.yml'), 'test')
        @ciphers                           = SymmetricEncryption::Config.extract_ciphers(config)
        @cipher_v2, @cipher_v1, @cipher_v0 = @ciphers
      end

      it 'matches config file for first cipher' do
        cipher = SymmetricEncryption.cipher
        assert @cipher_v2.send(:key)
        assert @cipher_v2.send(:iv)
        assert @cipher_v2.version
        assert_equal @cipher_v2.cipher_name, cipher.cipher_name
        assert_equal @cipher_v2.version, cipher.version
        assert_equal false, SymmetricEncryption.secondary_ciphers.include?(cipher)
      end

      it 'match config file for v1 cipher' do
        cipher = SymmetricEncryption.cipher(2)
        assert @cipher_v2.cipher_name
        assert @cipher_v2.version
        assert_equal @cipher_v2.cipher_name, cipher.cipher_name
        assert_equal @cipher_v2.version, cipher.version
        assert_equal false, SymmetricEncryption.secondary_ciphers.include?(cipher)
      end

      it 'match config file for v0 cipher' do
        cipher = SymmetricEncryption.cipher(0)
        assert @cipher_v0.cipher_name
        assert @cipher_v0.version
        assert_equal @cipher_v0.cipher_name, cipher.cipher_name
        assert_equal @cipher_v0.version, cipher.version
        assert_equal true, SymmetricEncryption.secondary_ciphers.include?(cipher)
      end
    end

    [:none, :base64, :base64strict, :base16].each do |encoding|
      describe "encoding: #{encoding}" do
        before do
          @social_security_number                            = '987654321'
          @social_security_number_encrypted                  =
            case encoding
            when :base64
              "QEVuQwIAS+8X1NRrqdfEIQyFHVPuVA==\n"
            when :base64strict
              'QEVuQwIAS+8X1NRrqdfEIQyFHVPuVA=='
            when :base16
              '40456e4302004bef17d4d46ba9d7c4210c851d53ee54'
            when :none
              "@EnC\x02\x00K\xEF\x17\xD4\xD4k\xA9\xD7\xC4!\f\x85\x1DS\xEET".force_encoding(Encoding.find('binary'))
            else
              raise "Add test for encoding: #{encoding}"
            end
          @social_security_number_encrypted_with_secondary_1 = "D1UCu38pqJ3jc0GvwJHiow==\n"
          @non_utf8                                          = "\xc2".force_encoding('binary')
          @encoding                                          = SymmetricEncryption.cipher.encoding
          SymmetricEncryption.cipher.encoding                = encoding
        end

        after do
          SymmetricEncryption.cipher.encoding = @encoding
        end

        it 'encrypt simple string' do
          assert_equal @social_security_number_encrypted, SymmetricEncryption.encrypt(@social_security_number)
        end

        it 'decrypt string' do
          assert decrypted = SymmetricEncryption.decrypt(@social_security_number_encrypted)
          assert_equal @social_security_number, decrypted
          assert_equal Encoding.find('utf-8'), decrypted.encoding, decrypted
        end

        it 'return BINARY encoding for non-UTF-8 encrypted data' do
          assert_equal Encoding.find('binary'), @non_utf8.encoding
          assert_equal true, @non_utf8.valid_encoding?
          assert encrypted = SymmetricEncryption.encrypt(@non_utf8)
          assert decrypted = SymmetricEncryption.decrypt(encrypted)
          assert_equal true, decrypted.valid_encoding?
          assert_equal Encoding.find('binary'), decrypted.encoding, decrypted
          assert_equal @non_utf8, decrypted
        end

        it 'return nil when encrypting nil' do
          assert_nil SymmetricEncryption.encrypt(nil)
        end

        it "return '' when encrypting ''" do
          assert_equal '', SymmetricEncryption.encrypt('')
        end

        it 'return nil when decrypting nil' do
          assert_nil SymmetricEncryption.decrypt(nil)
        end

        it "return '' when decrypting ''" do
          assert_equal '', SymmetricEncryption.decrypt('')
        end

        it 'determine if string is encrypted' do
          assert_equal true, SymmetricEncryption.encrypted?(@social_security_number_encrypted)
          assert_equal false, SymmetricEncryption.encrypted?(@social_security_number)
        end
      end
    end

    describe 'using select_cipher' do
      before do
        @social_security_number = '987654321'
        # Encrypt data without a header and encode with base64 which has a trailing '\n'
        @encrypted_0_ssn        = SymmetricEncryption.cipher(0).encode(SymmetricEncryption.cipher(0).binary_encrypt(@social_security_number, false, false, false))

        SymmetricEncryption.select_cipher do |encoded_str, decoded_str|
          # Use cipher version 0 if the encoded string ends with "\n" otherwise
          # use the current default cipher
          encoded_str.end_with?("\n") ? SymmetricEncryption.cipher(0) : SymmetricEncryption.cipher
        end
      end

      after do
        # Clear out select_cipher
        SymmetricEncryption.select_cipher
      end

      it 'decrypt string without a header using an old cipher' do
        assert_equal @social_security_number, SymmetricEncryption.decrypt(@encrypted_0_ssn)
      end
    end

    describe 'without select_cipher' do
      before do
        @social_security_number = '987654321'
        # Encrypt data without a header and encode with base64 which has a trailing '\n'
        assert @encrypted_0_ssn = SymmetricEncryption.cipher(0).encode(SymmetricEncryption.cipher(0).binary_encrypt(@social_security_number, false, false, false))
      end

      it 'decrypt string without a header using an old cipher' do
        assert_raises OpenSSL::Cipher::CipherError do
          SymmetricEncryption.decrypt(@encrypted_0_ssn)
        end
      end
    end

    describe 'random iv' do
      before do
        @social_security_number = '987654321'
      end

      it 'encrypt and then decrypt using random iv' do
        # Encrypt with random iv
        assert encrypted = SymmetricEncryption.encrypt(@social_security_number, true)
        assert_equal true, SymmetricEncryption.encrypted?(encrypted)
        assert_equal @social_security_number, SymmetricEncryption.decrypt(encrypted)
      end

      it 'encrypt and then decrypt using random iv with compression' do
        # Encrypt with random iv and compress
        assert encrypted = SymmetricEncryption.encrypt(@social_security_number, true, true)
        assert_equal true, SymmetricEncryption.encrypted?(encrypted)
        assert_equal @social_security_number, SymmetricEncryption.decrypt(encrypted)
      end
    end

    describe 'data types' do
      describe 'string' do
        before do
          @social_security_number = '987654321'
        end

        it 'encrypt and decrypt value to and from a string' do
          assert encrypted = SymmetricEncryption.encrypt(@social_security_number, false, false, :string)
          assert_equal true, SymmetricEncryption.encrypted?(encrypted)
          assert_equal @social_security_number, SymmetricEncryption.decrypt(encrypted, nil, :string)
        end
      end

      describe 'integer' do
        before do
          @age = 21
        end

        it 'encrypt and decrypt value to and from an integer' do
          assert encrypted = SymmetricEncryption.encrypt(@age, false, false, :integer)
          assert_equal true, SymmetricEncryption.encrypted?(encrypted)
          assert_equal @age, SymmetricEncryption.decrypt(encrypted, nil, :integer)
        end
      end

      describe 'float' do
        before do
          @miles = 2.5
        end

        it 'encrypt and decrypt value to and from a float' do
          assert encrypted = SymmetricEncryption.encrypt(@miles, false, false, :float)
          assert_equal true, SymmetricEncryption.encrypted?(encrypted)
          assert_equal @miles, SymmetricEncryption.decrypt(encrypted, nil, :float)
        end
      end

      describe 'decimal' do
        before do
          @account_balance = BigDecimal.new('12.58')
        end

        it 'encrypt and decrypt value to and from a BigDecimal' do
          assert encrypted = SymmetricEncryption.encrypt(@account_balance, false, false, :decimal)
          assert_equal true, SymmetricEncryption.encrypted?(encrypted)
          assert_equal @account_balance, SymmetricEncryption.decrypt(encrypted, nil, :decimal)
        end
      end

      describe 'datetime' do
        before do
          @checked_in_at = DateTime.new(2001, 11, 26, 20, 55, 54, "-5")
        end

        it 'encrypt and decrypt value to and from a DateTime' do
          assert encrypted = SymmetricEncryption.encrypt(@checked_in_at, false, false, :datetime)
          assert_equal true, SymmetricEncryption.encrypted?(encrypted)
          assert_equal @checked_in_at, SymmetricEncryption.decrypt(encrypted, nil, :datetime)
        end
      end

      describe 'time' do
        before do
          @closing_time = Time.new(2013, 01, 01, 22, 30, 00, "-04:00")
        end

        it 'encrypt and decrypt value to and from a Time' do
          assert encrypted = SymmetricEncryption.encrypt(@closing_time, false, false, :time)
          assert_equal true, SymmetricEncryption.encrypted?(encrypted)
          assert_equal @closing_time, SymmetricEncryption.decrypt(encrypted, nil, :time)
        end
      end

      describe 'date' do
        before do
          @birthdate = Date.new(1927, 04, 01)
        end

        it 'encrypt and decrypt value to and from a Date' do
          assert encrypted = SymmetricEncryption.encrypt(@birthdate, false, false, :date)
          assert_equal true, SymmetricEncryption.encrypted?(encrypted)
          assert_equal @birthdate, SymmetricEncryption.decrypt(encrypted, nil, :date)
        end
      end

      describe 'boolean' do
        describe 'when true' do
          before do
            @is_working = true
          end

          it 'encrypt and decrypt a true value to and from a boolean' do
            assert encrypted = SymmetricEncryption.encrypt(@is_working, false, false, :boolean)
            assert_equal true, SymmetricEncryption.encrypted?(encrypted)
            assert_equal @is_working, SymmetricEncryption.decrypt(encrypted, nil, :boolean)
          end
        end

        describe 'when false' do
          before do
            @is_broken = false
          end

          it 'encrypt and decrypt a false value to and from a boolean' do
            assert encrypted = SymmetricEncryption.encrypt(@is_broken, false, false, :boolean)
            assert_equal true, SymmetricEncryption.encrypted?(encrypted)
            assert_equal @is_broken, SymmetricEncryption.decrypt(encrypted, nil, :boolean)
          end
        end

        describe 'when yaml' do
          before do
            @test = {:a => :b}
          end

          it 'encrypt and decrypt a false value to and from a boolean' do
            assert encrypted = SymmetricEncryption.encrypt(@test, false, false, :yaml)
            assert_equal true, SymmetricEncryption.encrypted?(encrypted)
            assert_equal @test, SymmetricEncryption.decrypt(encrypted, nil, :yaml)
          end
        end

      end
    end

    describe '.generate_symmetric_key_files' do
      let(:params) { { private_rsa_key: 'rsa_key', key: 'key', iv: 'iv' } }
      let(:file_path) { File.join(File.dirname(__FILE__), 'config', 'symmetric-encryption.yml') }
      let(:cipher_config) { { encrypted_key: 'encrypted_key', encrypted_iv: 'encrypted_iv'} }

      let(:config) do
        {
          private_rsa_key: 'rsa_key',
          ciphers: [{ version: 1, always_add_header: true, key: 'key', iv: 'iv' }]
        }
      end

      it 'removes unused config keys before generate the random keys' do
        SymmetricEncryption::Config.expects(:read_config).with(file_path, 'test').returns(config)
        SymmetricEncryption::Cipher.expects(:generate_random_keys).with(params).returns(cipher_config)

        SymmetricEncryption.generate_symmetric_key_files(file_path, 'test')
      end
    end
  end

end
