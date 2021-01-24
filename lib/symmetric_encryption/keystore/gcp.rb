require "google/cloud/kms/v1"

module SymmetricEncryption
  module Keystore
    class Gcp
      include Utils::Files

      def self.generate_data_key(cipher_name:, app_name:, environment:, key_path:, version: 0)
        version >= 255 ? (version = 1) : (version += 1)

        dek       = SymmetricEncryption::Key.new(cipher_name: cipher_name)
        file_name = "#{key_path}/#{app_name}_#{environment}_v#{version}.encrypted_key"
        keystore  = new(
          key_file:    file_name,
          app_name:    app_name,
          environment: environment
        )
        keystore.write(dek.key)

        {
          keystore:    :gcp,
          cipher_name: dek.cipher_name,
          version:     version,
          key_file:    file_name,
          iv:          dek.iv,
          crypto_key:  keystore.crypto_key
        }
      end

      def initialize(key_file:, app_name: nil, environment: nil, key_encrypting_key: nil, crypto_key: nil, project_id: nil, credentials: nil, location_id: nil)
        @crypto_key  = crypto_key
        @app_name    = app_name
        @environment = environment
        @file_name   = key_file
        @project_id  = project_id
        @credentials = credentials
        @location_id = location_id
      end

      def read
        decrypt(read_file_and_decode(file_name))
      end

      def write(data_key)
        write_encoded_to_file(file_name, encrypt(data_key))
      end

      def crypto_key
        @crypto_key ||= self.class::KMS::KeyManagementServiceClient.crypto_key_path(project_id, location_id, app_name,
                                                                                    environment.to_s)
      end

      private

      KMS = Google::Cloud::Kms::V1

      attr_reader :app_name, :environment

      def encrypt(plaintext)
        client.encrypt(crypto_key, plaintext).ciphertext
      end

      def decrypt(ciphertext)
        client.decrypt(crypto_key, ciphertext).plaintext
      end

      def client
        self.class::KMS::KeyManagementServiceClient.new(timeout: 2, credentials: credentials)
      end

      def project_id
        @project_id ||= ENV["GOOGLE_CLOUD_PROJECT"]
        raise "GOOGLE_CLOUD_PROJECT must be set" if @project_id.nil?

        @project_id
      end

      def credentials
        @credentials ||= ENV["GOOGLE_CLOUD_KEYFILE"]
        raise "GOOGLE_CLOUD_KEYFILE must be set" if @credentials.nil?

        @credentials
      end

      def location_id
        @location_id ||= ENV["GOOGLE_CLOUD_LOCATION"] || "global"
      end
    end
  end
end
