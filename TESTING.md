## Installation

Install all needed gems to run the tests:

    appraisal install

The gems are installed into the global gem list.
The Gemfiles in the `gemfiles` folder are also re-generated.

## Run Tests

For all supported Rails/ActiveRecord versions:

    rake

Or for specific version one:

    appraisal rails_4.2 rake

Or for one particular test file

    appraisal rails_4.2 ruby test/active_record_test.rb

Or down to one test case

    appraisal rails_4.2 ruby test/active_record_test.rb -n "/permit replacing value/"
