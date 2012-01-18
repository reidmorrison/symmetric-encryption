require 'rake/clean'
require 'rake/testtask'
require 'date'

desc "Build gem"
task :gem  do |t|
  gemspec = Gem::Specification.new do |s|
    s.name        = 'symmetric-encryption'
    s.version     = '0.0.1'
    s.platform    = Gem::Platform::RUBY
    s.authors     = ['Reid Morrison']
    s.email       = ['reidmo@gmail.com']
    s.homepage    = 'https://github.com/ClarityServices/symmetric-encryption'
    s.date        = Date.today.to_s
    s.summary     = "Symmetric Encryption for Ruby, and Ruby on Rails"
    s.description = "Symmetric Encryption is a library to seamlessly enable symmetric encryption in a project, written in Ruby."
    s.files       = FileList["./**/*"].exclude('*.gem', './nbproject/*').map{|f| f.sub(/^\.\//, '')}
    s.has_rdoc    = true
  end
  Gem::Builder.new(gemspec).build
end

desc "Run Test Suite"
task :test do
  Rake::TestTask.new(:functional) do |t|
    t.test_files = FileList['test/*_test.rb']
    t.verbose    = true
  end

  Rake::Task['functional'].invoke
end
