namespace :symmetric_encryption do

  desc 'Decrypt the supplied string. Example: VALUE="Hello World" rake symmetric_encryption:decrypt'
  task :decrypt do
    puts "\nEncrypted: #{ENV['VALUE']}"
    puts "Decrypted: #{Symmetric::Encryption.decrypt(ENV['VALUE'])}\n\n"
  end

  desc 'Encrypt a value, such as a password. Example: rake symmetric_encryption:encrypt'
  task :encrypt do
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
    puts "\nEncrypted: #{Symmetric::Encryption.encrypt(password1)}\n\n"
  end

  desc 'Generate a random password and display its encrypted form. Example: rake symmetric_encryption:random_password'
  task :random_password do
    p = Symmetric::Encryption.random_password
    puts "\nGenerated Password: #{p}"
    puts "Encrypted: #{Symmetric::Encryption.encrypt(p)}\n\n"
  end

end
