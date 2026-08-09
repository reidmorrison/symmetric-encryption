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

desc "Regenerate docs/llms-full.txt from the docs markdown pages"
task :llms_full do
  pages  = %w[index guide configuration rails mongoid files cli key_rotation security api migrating]
  header = <<~HEADER
    # Symmetric Encryption - Complete Documentation

    > Symmetric Encryption encrypts data at rest in Ruby and Rails applications using OpenSSL, with the encryption keys held outside of the source code.

    This file concatenates every page of https://encryption.reidmorrison.com for consumption by AI assistants.
    It is generated from the markdown sources in docs/ by `bundle exec rake llms_full`; do not edit it directly.
    A per-page index is available at https://encryption.reidmorrison.com/llms.txt
  HEADER

  sections = pages.map do |page|
    text = File.read("docs/#{page}.md").
           sub(/\A---\n.*?\n---\n/m, ""). # Jekyll front matter
           gsub(/^\{:.*\}\n/, "").        # kramdown attribute lines ({:toc}, {:.no_toc}, ...)
           gsub(/^\* TOC\n/, "").
           gsub(/^\*\*Contents\*\*\n/, "").
           gsub(/^!\[.*\n/, "")           # images (relative paths, useless in plain text)
    "<!-- source: docs/#{page}.md -->\n\n#{text.strip}\n"
  end

  File.write("docs/llms-full.txt", ([header] + sections).join("\n\n---\n\n"))
  puts "Wrote docs/llms-full.txt (#{File.size('docs/llms-full.txt')} bytes)"
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
