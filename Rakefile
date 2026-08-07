# Setup bundler to avoid having to run bundle exec all the time.
require "rubygems"
require "bundler/setup"

require "rake/testtask"
require "rubocop/rake_task"
require_relative "lib/symmetric_encryption/version"

RuboCop::RakeTask.new

desc "Build the gem"
task :gem do
  system "gem build symmetric-encryption.gemspec"
end

desc "Build the gem, tag the release, and push it to rubygems"
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

# By default run Rubocop once, then the tests against all appraisals.
# Rubocop is deliberately not part of the inner default: its result does not depend on the
# Rails version, so running it per appraisal would just repeat the same work.
if !ENV["APPRAISAL_INITIALIZED"] && !ENV["TRAVIS"]
  require "appraisal"
  task default: %i[rubocop appraisal]
else
  task default: :test
end
