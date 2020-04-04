require "base64"
require "aws-sdk-kms"
module SymmetricEncryption
  module Utils
    # Wrap the AWS KMS client so that it automatically creates the Customer Master Key,
    # if one does not already exist.
    #
    # Map OpenSSL cipher names to AWS KMS key specs.
    class Aws
      attr_reader :master_key_alias, :client

      AWS_US_REGIONS = %w[us-east-1 us-east-2 us-west-1 us-west-2].freeze

      # TODO: Map to OpenSSL ciphers
      AWS_KEY_SPEC_MAP = {
        "aes-256-cbc" => "AES_256",
        "aes-128-cbc" => "AES_128"
      }.freeze

      # TODO: Move to Keystore::Aws
      # Rotate the Customer Master key in each of the supplied regions.
      # After the master key has been rotated, use `.write_key_files` to generate
      # a new DEK and re-encrypt with the new CMK in each region.
      # def self.rotate_master_key(master_key_alias:, cipher_name:, regions: AWS_US_REGIONS)
      #   Array(regions).collect do |region|
      #     key_manager = new(region: region, master_key_alias: master_key_alias, cipher_name: cipher_name)
      #     key_id      = key_manager.create_master_key
      #     key_manager.create_alias(key_id)
      #   end
      # end

      def initialize(region:, master_key_alias:)
        # Can region be read from environment?
        # Region is required for filename / env var name
        @client           = ::Aws::KMS::Client.new(region: region)
        @master_key_alias = master_key_alias
      end

      # Returns a new DEK encrypted using the CMK
      def generate_encrypted_data_key(cipher_name)
        auto_create_master_key do
          client.generate_data_key_without_plaintext(key_id: master_key_alias, key_spec: key_spec(cipher_name)).ciphertext_blob
        end
      end

      # Returns a new DEK in the clear
      def generate_data_key(cipher_name)
        auto_create_master_key do
          client.generate_data_key(key_id: master_key_alias, key_spec: key_spec(cipher_name)).plaintext
        end
      end

      # Decrypt data previously encrypted using the cmk
      def decrypt(encrypted_data)
        auto_create_master_key do
          client.decrypt(ciphertext_blob: encrypted_data).plaintext
        end
      end

      # Decrypt data previously encrypted using the cmk
      def encrypt(data)
        auto_create_master_key do
          client.encrypt(key_id: master_key_alias, plaintext: data).ciphertext_blob
        end
      end

      # Returns the AWS KMS key spec that matches the supplied OpenSSL cipher name
      def key_spec(cipher_name)
        key_spec = AWS_KEY_SPEC_MAP[cipher_name]
        raise("OpenSSL Cipher: #{cipher_name} has not yet been mapped to an AWS key spec.") unless key_spec

        key_spec
      end

      # Creates a new master key along with an alias that points to it.
      # Returns [String] the new master key id that was created.
      def create_master_key
        key_id = create_new_master_key
        create_alias(key_id)
        key_id
      end

      # Deletes the current master key and its alias.
      #
      # retention_days: Number of days to keep the CMK before completely destroying it.
      #
      # NOTE:
      #   Use with caution, only intended for testing purposes !!!
      def delete_master_key(retention_days: 30)
        key_info = client.describe_key(key_id: master_key_alias)
        ap key_info
        resp = client.schedule_key_deletion(key_id: key_info.key_metadata.key_id, pending_window_in_days: retention_days)
        ap client.delete_alias(alias_name: master_key_alias)
        resp.deletion_date
      rescue ::Aws::KMS::Errors::NotFoundException
        nil
      end

      private

      def whoami
        @whoami ||= `whoami`.strip
      rescue StandardError
        @whoami = "unknown"
      end

      # Creates a new Customer Master Key for Symmetric Encryption use.
      def create_new_master_key
        # TODO: Add error handling and retry

        resp = client.create_key(
          description: "Symmetric Encryption for Ruby Customer Masker Key",
          tags:        [
            {tag_key: "CreatedAt", tag_value: Time.now.to_s},
            {tag_key: "CreatedBy", tag_value: whoami}
          ]
        )
        resp.key_metadata.key_id
      end

      def create_alias(key_id)
        # TODO: Add error handling and retry
        # TODO: Move existing alias if any
        client.create_alias(alias_name: master_key_alias, target_key_id: key_id)
      end

      def auto_create_master_key
        attempt = 1
        yield
      rescue ::Aws::KMS::Errors::NotFoundException
        raise if attempt >= 2

        create_master_key
        attempt += 1
        retry
      end
    end
  end
end
