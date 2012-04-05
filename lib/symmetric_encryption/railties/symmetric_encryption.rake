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

  desc 'Generate new Symmetric key and initialization vector. Example: RAILS_ENV=production rake symmetric_encryption:generate_symmetric_keys'
  task :generate_symmetric_keys do
    SymmetricEncryption.generate_symmetric_key_files
  end

  desc 'Generate a random password and display its encrypted form. Example: rake symmetric_encryption:random_password'
  task :random_password => :environment do
    p = SymmetricEncryption.random_password
    puts "\nGenerated Password: #{p}"
    puts "Encrypted: #{SymmetricEncryption.encrypt(p)}\n\n"
  end

end
