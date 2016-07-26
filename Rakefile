require 'rake/clean'
require 'rake/testtask'

$LOAD_PATH.unshift File.expand_path('../lib', __FILE__)
require 'symmetric_encryption/version'

task :gem do
  system 'gem build symmetric-encryption.gemspec'
end

task :publish => :gem do
  system "git tag -a v#{SymmetricEncryption::VERSION} -m 'Tagging #{SymmetricEncryption::VERSION}'"
  system 'git push --tags'
  system "gem push symmetric-encryption-#{SymmetricEncryption::VERSION}.gem"
  system "rm symmetric-encryption-#{SymmetricEncryption::VERSION}.gem"
end

Rake::TestTask.new(:test) do |t|
  t.pattern = 'test/**/*_test.rb'
  t.verbose = true
  t.warning = false
end

task :default => :test
