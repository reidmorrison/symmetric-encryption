require "google/cloud/kms/v1"

module SymmetricEncryption
  module Keystore
    class Gcp
      include Utils::Files

      KMS = Google::Cloud::Kms::V1

      # permissions, owner, group:
      #   What the encrypted data key file is expected to look like on disk.
      #   See `SymmetricEncryption::Utils::FileAccess`.
      #   The file is created with the supplied permissions. Owner and group are only recorded in
      #   the returned configuration, since changing them requires privileges this process is not
      #   expected to have. They describe the environment the key file is deployed into.
      def self.generate_data_key(cipher_name:, app_name:, environment:, key_path:, version: 0, dek: nil,
                                 permissions: nil, owner: nil, group: nil, **_args)
        version >= 255 ? (version = 1) : (version += 1)

        dek     ||= SymmetricEncryption::Key.new(cipher_name: cipher_name)
        file_name = "#{key_path}/#{app_name}_#{environment}_v#{version}.encrypted_key"
        keystore  = new(
          key_file:    file_name,
          app_name:    app_name,
          environment: environment,
          permissions: permissions
        )
        keystore.write(dek.key)

        config = {
          keystore:    :gcp,
          cipher_name: dek.cipher_name,
          version:     version,
          key_file:    file_name,
          iv:          dek.iv,
          crypto_key:  keystore.crypto_key
        }
        {permissions: permissions, owner: owner, group: group}.each_pair do |name, value|
          config[name] = value unless value.nil?
        end
        config
      end

      # `key_encrypting_key` is accepted for interface compatibility only: Cloud KMS holds the
      # key encrypting key itself, so one can never be supplied here.
      #
      # permissions, owner, group:
      #   What the encrypted data key file is expected to look like on disk.
      #   See `SymmetricEncryption::Utils::FileAccess`.
      # rubocop:disable Lint/UnusedMethodArgument
      def initialize(key_file:, app_name: nil, environment: nil, key_encrypting_key: nil, crypto_key: nil, project_id: nil,
                     credentials: nil, location_id: nil, permissions: nil, owner: nil, group: nil)
        # rubocop:enable Lint/UnusedMethodArgument
        @crypto_key  = crypto_key
        @app_name    = app_name
        @environment = environment
        @file_name   = key_file
        @project_id  = project_id
        @credentials = credentials
        @location_id = location_id
        @file_access = Utils::FileAccess.new(permissions: permissions, owner: owner, group: group)
      end

      def read
        decrypt(read_file_and_decode(file_name))
      end

      def write(data_key)
        write_encoded_to_file(file_name, encrypt(data_key))
      end

      # Returns [String] the fully qualified name of the Cloud KMS key used to secure the data key.
      #
      # Example: projects/my-project/locations/global/keyRings/my_app/cryptoKeys/production
      #
      # Note: Built without a client so that the name is available before credentials are needed.
      def crypto_key
        @crypto_key ||= KMS::KeyManagementService::Paths.crypto_key_path(
          project:    project_id,
          location:   location_id,
          key_ring:   app_name,
          crypto_key: environment.to_s
        )
      end

      private

      attr_reader :app_name, :environment

      def encrypt(plaintext)
        client.encrypt(name: crypto_key, plaintext: plaintext).ciphertext
      end

      def decrypt(ciphertext)
        client.decrypt(name: crypto_key, ciphertext: ciphertext).plaintext
      end

      def client
        @client ||= KMS::KeyManagementService::Client.new do |config|
          config.credentials = credentials
          config.timeout     = 2
        end
      end

      def project_id
        @project_id ||= ENV.fetch("GOOGLE_CLOUD_PROJECT", nil)
        raise "GOOGLE_CLOUD_PROJECT must be set" if @project_id.nil?

        @project_id
      end

      def credentials
        @credentials ||= ENV.fetch("GOOGLE_CLOUD_KEYFILE", nil)
        raise "GOOGLE_CLOUD_KEYFILE must be set" if @credentials.nil?

        @credentials
      end

      def location_id
        @location_id ||= ENV["GOOGLE_CLOUD_LOCATION"] || "global"
      end
    end
  end
end
