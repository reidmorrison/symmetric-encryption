---
paths:
  - "test/**"
---

# Writing tests

Two things to know before writing tests here:

- `SymmetricEncryption.cipher` is module-level global state. Anything that calls `Config.load!` (directly, or through the CLI) replaces the ciphers `test_helper` set up and breaks whichever file runs next, since Minitest randomizes order. Save and restore `cipher` and `secondary_ciphers` around such tests, as [cli_test.rb](../../test/cli_test.rb) does.
- Minitest rejects `let` names that begin with `test` or that shadow a `Minitest::Spec` method (`value`, `name`, ...). That is why the existing helpers are named `the_test_path`, `the_config_file_name`, and so on.

The cloud keystores are covered offline by the `*_stubbed_test.rb` files, which need no credentials and make no network calls:

- AWS uses the SDK's own response stubbing (`Aws.config[:stub_responses]`). Prefer this over hand-written mocks: request parameters are still validated against the real KMS API model, so a misnamed argument fails the test.
- Cloud KMS has no equivalent, so [keystore/gcp_stubbed_test.rb](../../test/keystore/gcp_stubbed_test.rb) replaces the client with a stub that returns the real response protobufs and records the request arguments.
