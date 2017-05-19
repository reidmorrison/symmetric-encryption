require_relative 'test_helper'

class CipherTest < Minitest::Test
  describe SymmetricEncryption::Header do
    describe '#new' do
      it 'sets defaults' do
        header = SymmetricEncryption::Header.new
        assert_equal SymmetricEncryption.cipher.version, header.version
        refute header.compressed
        refute header.iv
        refute header.key
        refute header.cipher_name
        refute header.auth_tag
      end
    end

    describe '.present?' do
      it 'has a header' do

      end

      it 'does not have a header' do

      end
    end

    describe '#cipher' do
    end

    describe '#version' do
    end

    describe '#parse!' do
    end

    describe '#to_s' do
    end

    describe '#parse' do
    end
  end
end

