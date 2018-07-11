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
      attr_reader :app_name, :environment, :version, :key_path, :region, :cipher_name

      # Returns [Hash] a new keystore configuration after generating the data key.
      #
      # Increments the supplied version number by 1.
      #
      # Sample Hash layout returned:
      # {
      #   cipher_name: aes - 256 - cbc,
      #   version:     8,
      #   keystore:    :aws,
      #   key_files:   [
      #                  {region: blah1, file_name: "/etc/clarity/clarity_production_v6_blah1.encrypted_key"},
      #                  {region: blah2, file_name: "/etc/clarity/clarity_production_v6_blah2.encrypted_key"},
      #                ],
      #   iv:          'T80pYzD0E6e/bJCdjZ6TiQ=='
      # }
      def self.generate_data_key(version: 0,
        data_key: nil,
        regions: Utils::Aws::AWS_US_REGIONS,
        dek: nil,
        cipher_name:,
        **args)

        # TODO: Also support generating environment variables instead of files.

        version >= 255 ? (version = 1) : (version += 1)
        regions = Array(regions).dup

        key_files = []
        # Re-encrypt DEK in other regions using that regions CMK.
        regions.each do |region|
          keystore = new(region: region, version: version, **args)
          if dek
            data_key = keystore.aws.encrypt(dek.key)
          else
            # Generate new data key in the first region if not supplied.
            data_key = keystore.aws.generate_data_key(cipher_name)
            dek      = SymmetricEncryption::Key.new(cipher_name: cipher_name, key: data_key)
          end

          keystore.write(data_key)
          key_files << {region: region, file_name: keystore.data_key_file_name}
        end

        {
          keystore:    :aws,
          cipher_name: dek.cipher_name,
          version:     version,
          key_files:   key_files,
          iv:          dek.iv
        }
      end

      # Stores the Encryption key in a file.
      # Secures the Encryption key by encrypting it with a key encryption key.
      def initialize(region:, version:, environment:, app_name: 'symmetric-encryption', key_path: '~/.symmetric-encryption', key_encrypting_key: nil)
        @app_name    = app_name.downcase.strip
        @environment = environment.downcase.strip
        @version     = version.to_s.strip
        @key_path    = key_path
        @region      = region
        if key_encrypting_key
          raise(SymmetricEncryption::ConfigError, 'AWS KMS keystore encrypts the key itself, so does not support supplying a key_encrypting_key')
        end
      end

      # Alias pointing to the active version of the master key for that region.
      def master_key_alias
        @master_key_alias ||= "alias/symmetric-encryption/#{app_name}/#{environment}"
      end

      # Reads the data key environment variable, if present, otherwise a file.
      # Decrypts the key using the master key for this region.
      def read
        encoded_dek = ENV[data_key_env_var_name]

        if encoded_dek.nil? && ::File.exist?(data_key_file_name)
          # TODO: Validate that file is not globally readable.
          encoded_dek = ::File.open(data_key_file_name, 'rb', &:read)
        end

        unless encoded_dek
          raise(SymmetricEncryption::ConfigError, "Could not read the data key from either ENV['#{data_key_env_var_name}'] or #{data_key_file_name}")
        end

        encrypted_data_key = Base64.urlsafe_decode64(encoded_dek)
        aws.decrypt(encrypted_data_key)
      end

      # Encrypt and write the key to file.
      def write(data_key)
        encrypted_data_key = aws.encrypt(data_key)
        write_encrypted_key(encrypted_data_key)
      end

      # Writes an encrypted data key to file.
      def write_encrypted_key(encrypted_data_key)
        encoded_dek = Base64.urlsafe_encode64(encrypted_data_key)
        write_to_file(data_key_file_name, encoded_dek)
      end

      # Name of the environment variable that would hold the encoded encrypted data key.
      def data_key_env_var_name
        data_key_name.upcase.tr('-', '_')
      end

      # Name of the file that would hold the encoded encrypted data key.
      def data_key_file_name
        ::File.join(key_path, "#{data_key_name}.encrypted_key")
      end

      def aws
        @aws ||= Utils::Aws.new(region: region, master_key_alias: master_key_alias)
      end

      private

      def data_key_name
        "#{app_name}_#{environment}_#{region}_v#{version}"
      end

      # Write to the supplied file_name, backing up the existing file if present
      def write_to_file(file_name, data)
        path = ::File.dirname(file_name)
        ::FileUtils.mkdir_p(path) unless ::File.directory?(path)
        ::File.rename(file_name, "#{file_name}.#{Time.now.to_i}") if ::File.exist?(file_name)
        ::File.open(file_name, 'wb') { |file| file.write(data) }
      end

      # def create_data_key_env_var
      #   encrypted_dek = create_encrypted_data_key
      #   encoded_dek   = Base64.urlsafe_encode64(encrypted_dek)
      #   env_var       = data_key_env_var_name
      #   {env_var => encoded_dek}
      # end

    end
  end
end
