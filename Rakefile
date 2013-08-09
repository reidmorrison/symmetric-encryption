lib = File.expand_path('../lib/', __FILE__)
$:.unshift lib unless $:.include?(lib)

require 'rubygems'
require 'rubygems/package'
require 'rake/clean'
require 'rake/testtask'
require 'date'
require 'symmetric_encryption/version'

desc "Build gem"
task :gem  do |t|
  gemspec = Gem::Specification.new do |s|
    s.name        = 'symmetric-encryption'
    s.version     = SymmetricEncryption::VERSION
    s.platform    = Gem::Platform::RUBY
    s.authors     = ['Reid Morrison']
    s.email       = ['reidmo@gmail.com']
    s.homepage    = 'https://github.com/ClarityServices/symmetric-encryption'
    s.date        = Date.today.to_s
    s.summary     = "Symmetric Encryption for Ruby, and Ruby on Rails"
    s.description = "SymmetricEncryption supports encrypting ActiveRecord data, Mongoid data, passwords in configuration files, encrypting and decrypting of large files through streaming"
    s.files       = FileList["./**/*"].exclude(/.gem$/, /.log$/,/^nbproject/).map{|f| f.sub(/^\.\//, '')}
    s.license     = "Apache License V2.0"
    s.has_rdoc    = true
  end
  Gem::Package.build gemspec
end

desc "Run Test Suite"
task :test do
  Rake::TestTask.new(:functional) do |t|
    t.test_files = FileList['test/*_test.rb']
    t.verbose    = true
  end

  # For mongoid
  ENV['RACK_ENV'] = 'test'

  Rake::Task['functional'].invoke
end
