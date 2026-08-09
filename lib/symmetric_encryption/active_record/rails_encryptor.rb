module SymmetricEncryption
  module ActiveRecord
    # Decrypts values that Symmetric Encryption encrypted, from inside Active Record encryption.
    #
    # Supply it as a previous encryption scheme so that an application can move to Active Record
    # encryption without having to re-encrypt its data first:
    #
    #   class User < ApplicationRecord
    #     encrypts :ssn, previous: [{encryptor: SymmetricEncryption::ActiveRecord::RailsEncryptor.new}]
    #   end
    #
    # Active Record reads every value with its own encryptor first, and falls back to the previous
    # schemes when that fails. Values already in the database are therefore read by Symmetric
    # Encryption, and every value written from then on is encrypted by Active Record, so the data
    # migrates as records are saved. Re-save the remaining rows to finish the migration, then
    # remove `previous:` and this gem's configuration.
    #
    # Notes:
    # * Decrypt only. It never writes a value in Symmetric Encryption's format, so that a
    #   migration cannot silently go backwards. Writing is Active Record encryption's job.
    # * `SymmetricEncryption.load!`, or the Railtie, still has to run, since this reads the keys
    #   from `symmetric-encryption.yml` exactly as the rest of the gem does.
    # * A deterministic attribute has to be declared `deterministic: {fixed: false}`. Active
    #   Record encrypts with the _oldest_ scheme for `deterministic: true`, which would mean
    #   writing new values with this encryptor, and it refuses to write.
    # * Only for attributes whose cipher uses one of the base64 encodings, which is the default.
    #   A cipher using `encoding: :none` returns binary data that does not belong in the text
    #   column that Active Record encryption expects.
    class RailsEncryptor
      # Never encrypts. See the class documentation.
      #
      # The keyword arguments are part of the interface Active Record encryption calls, so they
      # are declared even though nothing here reads them.
      def encrypt(_clear_text, key_provider: nil, cipher_options: {}) # rubocop:disable Lint/UnusedMethodArgument
        raise(
          ::ActiveRecord::Encryption::Errors::Encryption,
          "SymmetricEncryption::ActiveRecord::RailsEncryptor only decrypts, so that data cannot be written back " \
          "in Symmetric Encryption's format once it is being migrated to Active Record encryption. Active Record " \
          "encrypts a deterministic attribute with the oldest scheme, which is what reaches this encryptor. " \
          "Declare the attribute `deterministic: {fixed: false}` to have it encrypted with the current scheme."
        )
      end

      # Returns [String] the decrypted value.
      #
      # Raises ActiveRecord::Encryption::Errors::Decryption when the value was not encrypted by
      # Symmetric Encryption, or cannot be decrypted by the configured ciphers. Active Record only
      # moves on to the next previous scheme for its own error classes, so every failure has to be
      # translated into one, whatever raised it. The original class and message are kept, since a
      # failure here is as likely to be a missing key as it is to be a value in another format.
      #
      # The keyword arguments are part of the interface Active Record encryption calls, so they
      # are declared even though the keys come from `symmetric-encryption.yml` instead.
      def decrypt(encrypted_text, key_provider: nil, cipher_options: {}) # rubocop:disable Lint/UnusedMethodArgument
        SymmetricEncryption.decrypt(encrypted_text)
      rescue StandardError => e
        raise(::ActiveRecord::Encryption::Errors::Decryption, "#{e.class}: #{e.message}")
      end

      # Returns [true|false] whether the value was encrypted by Symmetric Encryption.
      #
      # Only reliable for values that carry a header, as for `SymmetricEncryption.encrypted?`.
      def encrypted?(text)
        SymmetricEncryption.encrypted?(text)
      end

      # Values are returned as text, since the base64 encodings are the only ones supported here.
      def binary?
        false
      end
    end
  end
end
