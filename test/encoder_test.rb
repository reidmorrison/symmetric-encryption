require_relative 'test_helper'

# Unit Test for SymmetricEncryption
#
class EncoderTest < Minitest::Test
  describe SymmetricEncryption::Encoder do
    %i[none base64 base64strict base16].each do |encoding|
      describe "encoding: #{encoding}" do
        before do
          @data         = '987654321'
          @data_encoded =
            case encoding
            when :base64
              "OTg3NjU0MzIx\n"
            when :base64strict
              'OTg3NjU0MzIx'
            when :base16
              '393837363534333231'
            when :none
              @data
            end
          @encoder      = SymmetricEncryption::Encoder[encoding]
          @non_utf8     = "\xc2".force_encoding('binary')
        end

        it 'correctly encodes' do
          assert_equal @data_encoded, @encoder.encode(@data)
          assert_equal Encoding.find('UTF-8'), @data_encoded.encoding
        end

        it 'return BINARY encoding for non-UTF-8 data' do
          assert_equal Encoding.find('binary'), @non_utf8.encoding
          assert @non_utf8.valid_encoding?
          assert encoded = @encoder.encode(@non_utf8)
          assert decoded = @encoder.decode(encoded)
          assert decoded.valid_encoding?
          assert_equal Encoding.find('binary'), decoded.encoding, decoded
          assert_equal @non_utf8, decoded
        end

        it 'return nil when encoding nil' do
          assert_nil @encoder.encode(nil)
        end

        it "return '' when encoding ''" do
          assert_equal '', @encoder.encode('')
        end

        it 'return nil when decoding nil' do
          assert_nil @encoder.decode(nil)
        end

        it "return '' when decoding ''" do
          assert_equal '', @encoder.decode('')
        end
      end
    end
  end
end
