require_relative "../test_helper"

module SymmetricEncryption
  module Utils
    class ReEncryptFilesTest < Minitest::Test
      describe SymmetricEncryption::Utils::ReEncryptFiles do
        let :the_test_path do
          "tmp/re_encrypt_files_test"
        end

        # Version of a secondary cipher in the test config, used to create "old" encrypted values.
        let :old_version do
          6
        end

        let :re_encrypt do
          SymmetricEncryption::Utils::ReEncryptFiles.new(version: nil)
        end

        let :old_encrypted do
          SymmetricEncryption.cipher(old_version).encrypt("Hello World")
        end

        before do
          FileUtils.rm_rf(the_test_path)
          FileUtils.makedirs(the_test_path)
        end

        after do
          FileUtils.rm_rf(the_test_path)
        end

        describe "#initialize" do
          it "defaults to the current cipher" do
            assert_equal SymmetricEncryption.cipher.version, re_encrypt.version
            assert_equal SymmetricEncryption.cipher.version, re_encrypt.cipher.version
          end

          it "uses the supplied version" do
            assert_equal old_version, SymmetricEncryption::Utils::ReEncryptFiles.new(version: old_version).version
          end

          it "raises when the version is unknown" do
            assert_raises(ArgumentError) { SymmetricEncryption::Utils::ReEncryptFiles.new(version: 99) }
          end
        end

        describe "#re_encrypt" do
          it "re-encrypts with the new cipher" do
            new_encrypted = re_encrypt.re_encrypt(old_encrypted)

            refute_equal old_encrypted, new_encrypted
            assert_equal "Hello World", SymmetricEncryption.decrypt(new_encrypted)
            assert_equal SymmetricEncryption.cipher.version, SymmetricEncryption.header(new_encrypted).version
          end

          it "returns the original value when it cannot be decrypted" do
            garbage = "#{SymmetricEncryption.cipher.encoded_magic_header}NotEncryptedAtAll"
            assert_equal garbage, re_encrypt.re_encrypt(garbage)
          end
        end

        describe "#re_encrypt_lines" do
          it "replaces every encrypted value it finds" do
            lines = "password: #{old_encrypted}\nusername: jack\nsecret: #{old_encrypted}\n"

            hits, output = re_encrypt.re_encrypt_lines(lines)

            assert_equal 2, hits
            assert_includes output, "username: jack"
            refute_includes output, old_encrypted
            output.each_line do |line|
              next unless line.start_with?("password: ", "secret: ")

              assert_equal "Hello World", SymmetricEncryption.decrypt(line.split(": ").last.strip)
            end
          end

          it "leaves lines without encrypted values unchanged" do
            lines = "username: jack\npassword: not encrypted\n"

            hits, output = re_encrypt.re_encrypt_lines(lines)

            assert_equal 0, hits
            assert_equal lines, output
          end

          it "leaves lines with invalid encoding unchanged" do
            lines = "username: jack\nbinary: \xC3\x28\n".dup.force_encoding(SymmetricEncryption::BINARY_ENCODING)

            hits, output = re_encrypt.re_encrypt_lines(lines)

            assert_equal 0, hits
            assert_equal lines.bytes, output.bytes
          end
        end

        describe "#re_encrypt_contents" do
          let :file_name do
            "#{the_test_path}/application.yml"
          end

          it "rewrites the file and returns the number of values re-encrypted" do
            File.write(file_name, "password: #{old_encrypted}\n")

            assert_equal 1, re_encrypt.re_encrypt_contents(file_name)

            new_value = File.read(file_name).split(": ").last.strip
            refute_equal old_encrypted, new_value
            assert_equal "Hello World", SymmetricEncryption.decrypt(new_value)
          end

          it "does not rewrite a file without encrypted values" do
            File.write(file_name, "username: jack\n")

            assert_equal 0, re_encrypt.re_encrypt_contents(file_name)
            assert_equal "username: jack\n", File.read(file_name)
          end

          it "skips files larger than 256KB" do
            File.write(file_name, "password: #{old_encrypted}\n#{'#' * 256 * 1024}")

            assert_equal 0, re_encrypt.re_encrypt_contents(file_name)
          end
        end

        describe "#re_encrypt_file" do
          let :file_name do
            "#{the_test_path}/encrypted.dat"
          end

          it "re-encrypts an entire encrypted file" do
            SymmetricEncryption::Writer.write(file_name, "Hello World", version: old_version)

            re_encrypt.re_encrypt_file(file_name)

            assert_equal "Hello World", SymmetricEncryption::Reader.read(file_name)
            ::File.open(file_name, "rb") do |file|
              assert_equal SymmetricEncryption.cipher.version, SymmetricEncryption::Reader.new(file).version
            end
          end

          it "does not leave the temp file behind when it fails" do
            File.write(file_name, "Not an encrypted file")

            assert_raises(StandardError) { re_encrypt.re_encrypt_file(file_name) }
            assert_empty Dir["#{the_test_path}/__re_encrypting_*"]
          end
        end

        describe "#process_directory" do
          it "re-encrypts values within files" do
            File.write("#{the_test_path}/application.yml", "password: #{old_encrypted}\n")

            out, = capture_io { re_encrypt.process_directory("#{the_test_path}/*.yml") }

            assert_includes out, "Re-encrypted 1 encrypted value(s) in"
            assert_equal "Hello World", SymmetricEncryption.decrypt(File.read("#{the_test_path}/application.yml").split(": ").last.strip)
          end

          it "re-encrypts whole files encrypted with an older version" do
            file_name = "#{the_test_path}/encrypted.dat"
            SymmetricEncryption::Writer.write(file_name, "Hello World", version: old_version)

            out, = capture_io { re_encrypt.process_directory("#{the_test_path}/*.dat") }

            assert_includes out, "Re-encrypting entire file"
            assert_equal "Hello World", SymmetricEncryption::Reader.read(file_name)
          end

          it "skips files already encrypted with the current version" do
            file_name = "#{the_test_path}/encrypted.dat"
            SymmetricEncryption::Writer.write(file_name, "Hello World", version: SymmetricEncryption.cipher.version)

            out, = capture_io { re_encrypt.process_directory("#{the_test_path}/*.dat") }

            assert_includes out, "Skipping already re-encrypted file"
          end

          it "skips directories" do
            FileUtils.makedirs("#{the_test_path}/subdir")

            out, = capture_io { re_encrypt.process_directory("#{the_test_path}/*") }

            assert_empty out
          end
        end
      end
    end
  end
end
