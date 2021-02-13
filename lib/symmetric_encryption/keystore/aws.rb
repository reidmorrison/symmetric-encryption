require "aws-sdk-kms"
module SymmetricEncryption
  module Keystore
    # Support AWS Key Management Service (KMS)
    #
    # Terms:
    #   Aws
    #     Amazon Web Services.
    #
    #   CMK
    #     Customer Master Key.
    #     Master key to encrypt and decrypt data, specifically the DEK in this case.
    #     Stored in AWS, cannot be exported.
    #
    #   DEK
    #     Data Encryption Key.
    #     Key used to encrypt local data.
    #     Encrypted with the CMK and stored locally.
    #
    #   KMS
    #     Key Management Service.
    #     For generating and storing the CMK.
    #     Used to encrypt and decrypt the DEK.
    #
    # Recommended reading:
    #
    # Concepts:
    #   https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html
    #
    # Overview:
    #   https://docs.aws.amazon.com/kms/latest/developerguide/overview.html
    #
    # Process:
    # 1. Create a customer master key (CMK) along with an alias for use by Symmetric Encryption.
    #     - Note: CMK is region specific.
    #     - Stored exclusively in AWS KMS, cannot be exported.
    #
    # 2. Generate and encrypt a data encryption key (DEK).
    #     - CMK is used to encrypt the DEK.
    #     - Encrypted DEK is stored locally.
    #     - Encrypted DEK is region specific.
    #       - DEK can be shared, but then must be re-encrypted in each region.
    #     - Shared DEK across regions for database replication.
    #     - List of regions to publish DEK to during generation / key-rotation.
    #     - DEK must be encrypted with CMK in each region consecutively.
    #
    # Warning:
    #   If access to the AWS KMS is ever lost, then it is not possible to decrypt any encrypted data.
    #   Examples:
    #     - Loss of access to AWS accounts.
    #     - Loss of region(s) in which master keys are stored.
    class Aws
      include Utils::Files

      attr_reader :region, :key_files, :master_key_alias

      # Returns [Hash] a new keystore configuration after generating the data key.
      #
      # Increments the supplied version number by 1.
      #
      # Sample Hash layout returned:
      # {
      #   cipher_name: aes-256-cbc,
      #   version:     8,
      #   keystore:    :aws,
      #   master_key_alias: 'alias/symmetric-encryption/application/production',
      #   key_files:   [
      #                  {region: blah1, file_name: "~/symmetric-encryption/application_production_blah1_v6.encrypted_key"},
      #                  {region: blah2, file_name: "~/symmetric-encryption/application_production_blah2_v6.encrypted_key"},
      #                ],
      #   iv:          'T80pYzD0E6e/bJCdjZ6TiQ=='
      # }
      def self.generate_data_key(cipher_name:, app_name:, environment:, key_path:, version: 0,
                                 regions: Utils::Aws::AWS_US_REGIONS,
                                 dek: nil,
                                 **_args)

        # TODO: Also support generating environment variables instead of files.

        version >= 255 ? (version = 1) : (version += 1)
        regions = Array(regions).dup

        master_key_alias = master_key_alias(app_name, environment)

        # File per region for holding the encrypted data key
        key_files = regions.collect do |region|
          file_name = "#{app_name}_#{environment}_#{region}_v#{version}.encrypted_key"
          {region: region, file_name: ::File.join(key_path, file_name)}
        end

        keystore = new(key_files: key_files, master_key_alias: master_key_alias)
        unless dek
          data_key = keystore.aws(regions.first).generate_data_key(cipher_name)
          dek      = Key.new(key: data_key, cipher_name: cipher_name)
        end
        keystore.write(dek.key)

        {
          keystore:         :aws,
          cipher_name:      dek.cipher_name,
          version:          version,
          master_key_alias: master_key_alias,
          key_files:        key_files,
          iv:               dek.iv
        }
      end

      # Alias pointing to the active version of the master key for that region.
      def self.master_key_alias(app_name, environment)
        @master_key_alias ||= "alias/symmetric-encryption/#{app_name}/#{environment}"
      end

      # Stores the Encryption key in a file.
      # Secures the Encryption key by encrypting it with a key encryption key.
      def initialize(key_files:, master_key_alias:, region: nil, key_encrypting_key: nil)
        @key_files        = key_files
        @master_key_alias = master_key_alias
        @region           = region || ENV["AWS_REGION"] || ENV["AWS_DEFAULT_REGION"] || ::Aws.config[:region]
        if key_encrypting_key
          raise(SymmetricEncryption::ConfigError,
                "AWS KMS keystore encrypts the key itself, so does not support supplying a key_encrypting_key")
        end
      end

      # Reads the data key environment variable, if present, otherwise a file.
      # Decrypts the key using the master key for this region.
      def read
        key_env_var = "#{app_name}_#{environment}_#{region}_v#{version}".upcase.tr("-", "_")
        if ENV[key_env_var].present?
          encrypted_data_key = decode64(ENV[key_env_var])
        else
          key_file = key_files.find { |i| i[:region] == region }
          raise(SymmetricEncryption::ConfigError, "region: #{region} not available in the supplied key_files") unless key_file
          file_name = key_file[:file_name]
          encrypted_data_key = read_file_and_decode(file_name)
        end

        aws(region).decrypt(encrypted_data_key)
      end

      # Encrypt and write the data key to the file for each region.
      def write(data_key)
        key_files.each do |key_file|
          region    = key_file[:region]
          file_name = key_file[:file_name]

          raise(ArgumentError, "region and file_name are mandatory for each key_file entry") unless region && file_name

          encrypted_data_key = aws(region).encrypt(data_key)
          write_encoded_to_file(file_name, encrypted_data_key)
        end
      end

      def aws(region)
        Utils::Aws.new(region: region, master_key_alias: master_key_alias)
      end
    end
  end
end
