require 'rake/clean'
require 'rake/testtask'

$LOAD_PATH.unshift File.expand_path("../lib", __FILE__)
require 'symmetric_encryption/version'

task :gem do
  system "gem build symmetric-encryption.gemspec"
end

task :publish => :gem do
  system "git tag -a v#{SymmetricEncryption::VERSION} -m 'Tagging #{SymmetricEncryption::VERSION}'"
  system "git push --tags"
  system "gem push symmetric-encryption-#{SymmetricEncryption::VERSION}.gem"
  system "rm symmetric-encryption-#{SymmetricEncryption::VERSION}.gem"
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

task :default => :test
