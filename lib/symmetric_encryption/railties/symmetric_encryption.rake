namespace :symmetric_encryption do

  desc 'Decrypt the supplied string. Example: VALUE="_encrypted_string_" rake symmetric_encryption:decrypt'
  task :decrypt => :environment do
    puts "\nEncrypted: #{ENV['VALUE']}"
    puts "Decrypted: #{SymmetricEncryption.decrypt(ENV['VALUE'])}\n\n"
  end

  desc 'Encrypt a value, such as a password. Example: rake symmetric_encryption:encrypt'
  task :encrypt => :environment do
    require 'highline'
    password1 = nil
    password2 = 0

    while password1 != password2
      password1 = HighLine.new.ask("Enter the value to encrypt:") { |q| q.echo = "*" }
      password2 = HighLine.new.ask("Re-enter the value to encrypt:") { |q| q.echo = "*" }

      if (password1 != password2)
        puts "Passwords do not match, please try again"
      end
    end
    puts "\nEncrypted: #{SymmetricEncryption.encrypt(password1)}\n\n"
  end

  desc 'Generate a random password and display its encrypted form. Example: rake symmetric_encryption:random_password'
  task :random_password => :environment do
    p = SymmetricEncryption.random_password
    puts "\nGenerated Password: #{p}"
    puts "Encrypted: #{SymmetricEncryption.encrypt(p)}\n\n"
  end

  desc 'Decrypt a file. Example: INFILE="encrypted_filename" OUTFILE="filename" rake symmetric_encryption:decrypt_file'
  task :decrypt_file => :environment do
    input_filename  = ENV['INFILE']
    output_filename = ENV['OUTFILE']
    block_size      = ENV['BLOCKSIZE'] || 65535

    if input_filename && output_filename
      puts "\nDecrypting file: #{input_filename} and writing to: #{output_filename}\n\n"
      ::File.open(output_filename, 'wb') do |output_file|
        SymmetricEncryption::Reader.open(input_filename) do |input_file|
          while !input_file.eof?
            output_file.write(input_file.read(block_size))
          end
        end
      end
      puts "\n#{output_filename} now contains the decrypted contents of #{input_filename}\n\n"
    else
      puts "Missing input and/or output filename. Usage:"
      puts '  INFILE="encrypted_filename" OUTFILE="filename" rake symmetric_encryption:decrypt_file'
    end
  end

  desc 'Encrypt a file. Example: INFILE="filename" OUTFILE="encrypted_filename" rake symmetric_encryption:encrypt_file'
  task :encrypt_file => :environment do
    input_filename  = ENV['INFILE']
    output_filename = ENV['OUTFILE']
    compress        = (ENV['COMPRESS'] != nil)
    block_size      = ENV['BLOCKSIZE'] || 65535

    if input_filename && output_filename
      puts "\nEncrypting file: #{input_filename} and writing to: #{output_filename}\n\n"
      ::File.open(input_filename, 'rb') do |input_file|
        SymmetricEncryption::Writer.open(output_filename, :compress => compress) do |output_file|
          while !input_file.eof?
            output_file.write(input_file.read(block_size))
          end
        end
      end
      puts "\n#{output_filename} now contains the encrypted #{"and compressed " if compress}contents of #{input_filename}\n\n"
    else
      puts "Missing input and/or output filename. Usage:"
      puts '  INFILE="filename" OUTFILE="encrypted_filename" rake symmetric_encryption:encrypt_file'
      puts "To compress the file before encrypting:"
      puts '  COMPRESS=1 INFILE="filename" OUTFILE="encrypted_filename" rake symmetric_encryption:encrypt_file'
    end
  end

end
