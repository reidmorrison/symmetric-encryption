require_relative 'test_helper'

# Tests for SymmetricEncryption::Cipher
class GenerateTest < Minitest::Test
  ['aes-128-cbc'].each do |cipher_name|
    #['aes-128-cbc', 'aes-128-gcm'].each do |cipher_name|
    describe "Cipher: #{cipher_name}" do
      describe '.generate_random_keys' do
        describe 'with wrong params' do
          it 'raises ArgumentError' do
            error = assert_raises ArgumentError do
              SymmetricEncryption::Cipher.generate_random_keys(wrong_params: '')
            end

            assert_equal "SymmetricEncryption::Cipher Invalid options {:wrong_params=>\"\"}", error.message
          end
        end

        describe 'without keys' do
          it 'creates new keys' do
            h = SymmetricEncryption::Cipher.generate_random_keys
            assert_equal 'aes-256-cbc', h[:cipher_name]
            assert_equal :base64strict, h[:encoding]
            assert h.has_key?(:key), h
            assert h.has_key?(:iv), h
          end
        end

        describe 'with keys' do
          it 'creates new keys' do
            h = SymmetricEncryption::Cipher.generate_random_keys(key: '', iv: '')
            assert_equal 'aes-256-cbc', h[:cipher_name]
            assert_equal :base64strict, h[:encoding]
            assert h.has_key?(:key), h
            assert h.has_key?(:iv), h
          end
        end

        describe 'with encrypted keys' do
          it 'creates new encrypted keys' do
            key_encryption_key = SymmetricEncryption::KeyEncryptionKey.generate
            h                  = SymmetricEncryption::Cipher.generate_random_keys(
              cipher_name:     cipher_name,
              encrypted_key:   '',
              encrypted_iv:    '',
              private_rsa_key: key_encryption_key
            )
            assert_equal cipher_name, h[:cipher_name]
            assert_equal :base64strict, h[:encoding]
            assert h.has_key?(:encrypted_key), h
            assert h.has_key?(:encrypted_iv), h
          end

          it 'exception on missing rsa key' do
            assert_raises SymmetricEncryption::ConfigError do
              SymmetricEncryption::Cipher.generate_random_keys(
                encrypted_key: '',
                encrypted_iv:  ''
              )
            end
          end
        end

        describe 'with files' do
          before do
            @key_filename = 'blah.key'
            @iv_filename  = 'blah.iv'
          end

          after do
            File.delete(@key_filename) if File.exist?(@key_filename)
            File.delete(@iv_filename) if File.exist?(@iv_filename)
          end

          it 'creates new files' do
            key_encryption_key = SymmetricEncryption::KeyEncryptionKey.generate
            h                  = SymmetricEncryption::Cipher.generate_random_keys(
              cipher_name:     cipher_name,
              key_filename:    @key_filename,
              iv_filename:     @iv_filename,
              private_rsa_key: key_encryption_key
            )
            assert_equal cipher_name, h[:cipher_name]
            assert_equal :base64strict, h[:encoding]
            assert h.has_key?(:key_filename), h
            assert h.has_key?(:iv_filename), h
            assert File.exist?(@key_filename)
            assert File.exist?(@iv_filename)
          end

          it 'exception on missing rsa key' do
            assert_raises SymmetricEncryption::ConfigError do
              SymmetricEncryption::Cipher.generate_random_keys(
                key_filename: @key_filename,
                iv_filename:  @iv_filename
              )
            end
          end
        end
      end
    end
  end
end
