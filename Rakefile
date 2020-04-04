# Setup bundler to avoid having to run bundle exec all the time.
require "rubygems"
require "bundler/setup"

require "rake/testtask"
require_relative "lib/symmetric_encryption/version"

task :gem do
  system "gem build symmetric-encryption.gemspec"
end

task publish: :gem do
  system "git tag -a v#{SymmetricEncryption::VERSION} -m 'Tagging #{SymmetricEncryption::VERSION}'"
  system "git push --tags"
  system "gem push symmetric-encryption-#{SymmetricEncryption::VERSION}.gem"
  system "rm symmetric-encryption-#{SymmetricEncryption::VERSION}.gem"
end

Rake::TestTask.new(:test) do |t|
  t.pattern = "test/**/*_test.rb"
  t.verbose = true
  t.warning = false
end

# By default run tests against all appraisals
if !ENV["APPRAISAL_INITIALIZED"] && !ENV["TRAVIS"]
  require "appraisal"
  task default: :appraisal
else
  task default: :test
end
