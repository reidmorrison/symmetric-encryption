lib = File.expand_path('../lib/', __FILE__)
$:.unshift lib unless $:.include?(lib)

require 'rubygems'
require 'rubygems/package'
require 'rake/clean'
require 'rake/testtask'
require 'symmetric_encryption/version'

desc "Build gem"
task :gem  do |t|
  Gem::Package.build(Gem::Specification.load('symmetric-encryption.gemspec'))
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
