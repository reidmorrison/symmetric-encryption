---
layout: default
---

### Large File Encryption

Example: Read and decrypt a line at a time from a file

```ruby
SymmetricEncryption::Reader.open('encrypted_file') do |file|
  file.each_line do |line|
     puts line
  end
end
```

Example: Encrypt and write data to a file

```ruby
SymmetricEncryption::Writer.open('encrypted_file') do |file|
  file.write "Hello World\n"
  file.write "Keep this secret"
end
```

Example: Compress, Encrypt and write data to a file

```ruby
SymmetricEncryption::Writer.open('encrypted_compressed.zip', compress: true) do |file|
  file.write "Hello World\n"
  file.write "Compress this\n"
  file.write "Keep this safe and secure\n"
end
```
