require_relative "../test_helper"

module SymmetricEncryption
  module Utils
    class FilesTest < Minitest::Test
      describe SymmetricEncryption::Utils::Files do
        # Utils::Files is a mixin of private helpers shared by the file based keystores.
        let :subject do
          Class.new do
            include SymmetricEncryption::Utils::Files

            public :read_file_and_decode, :write_encoded_to_file, :encode64, :decode64, :read_from_file, :write_to_file
          end.new
        end

        let :the_test_path do
          "tmp/files_test"
        end

        let :file_name do
          "#{the_test_path}/tester.key"
        end

        before do
          FileUtils.rm_rf(the_test_path)
          FileUtils.makedirs(the_test_path)
        end

        after do
          FileUtils.rm_rf(the_test_path)
        end

        describe "#encode64 and #decode64" do
          it "round trips binary data" do
            data = SymmetricEncryption::Key.new.key

            encoded = subject.encode64(data)
            refute_equal data, encoded
            assert_equal data, subject.decode64(encoded)
          end

          it "encodes without newlines" do
            refute_includes subject.encode64("A" * 100), "\n"
          end
        end

        describe "#write_encoded_to_file and #read_file_and_decode" do
          it "round trips the key" do
            subject.write_encoded_to_file(file_name, "1234567890ABCDEF")

            assert_equal "1234567890ABCDEF", subject.read_file_and_decode(file_name)
          end

          it "writes the file readable only by its owner" do
            subject.write_encoded_to_file(file_name, "1234567890ABCDEF")

            assert_equal "100600", File.stat(file_name).mode.to_s(8)
          end

          it "raises when no file name is supplied" do
            error = assert_raises(SymmetricEncryption::ConfigError) { subject.read_file_and_decode(nil) }

            assert_includes error.message, "file_name is mandatory"
          end

          it "raises when the file does not exist" do
            error = assert_raises(SymmetricEncryption::ConfigError) { subject.read_file_and_decode("#{the_test_path}/missing.key") }

            assert_includes error.message, "could not be found"
          end
        end

        describe "#write_to_file" do
          it "creates missing directories" do
            nested = "#{the_test_path}/a/b/tester.key"
            subject.write_to_file(nested, "data")

            assert_equal "data", subject.read_from_file(nested)
          end

          it "backs up an existing file" do
            subject.write_to_file(file_name, "original")
            subject.write_to_file(file_name, "replacement")

            assert_equal "replacement", subject.read_from_file(file_name)
            backups = Dir["#{file_name}.*"]
            assert_equal 1, backups.size
            assert_equal "original", File.binread(backups.first)
          end
        end

        describe "#read_from_file" do
          it "raises a config error when the file is missing" do
            error = assert_raises(SymmetricEncryption::ConfigError) { subject.read_from_file("#{the_test_path}/missing.key") }

            assert_includes error.message, "not found or readable"
          end
        end
      end
    end
  end
end
