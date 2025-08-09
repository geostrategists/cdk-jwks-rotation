import type { S3Client } from "@aws-sdk/client-s3";
import type { SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import { getSecretValue, regenerateAndPublishJwks } from "./utils";

export async function cleanupExpiredKeys(
  secretsClient: SecretsManagerClient,
  s3Client: S3Client,
  secretArn: string,
): Promise<void> {
  console.log("Starting cleanup of expired keys");

  const currentSecret = await getSecretValue(secretsClient, {
    SecretId: secretArn,
    VersionStage: "AWSCURRENT",
  });
  if (!currentSecret) {
    console.log("No current secret found, skipping cleanup");
    return;
  }

  try {
    await regenerateAndPublishJwks(secretsClient, s3Client, secretArn, {
      currentSecret: currentSecret.secretValue,
    });
    console.log("Cleanup completed via JWKS regeneration");
  } catch (error) {
    console.error("Error during cleanup:", error);
    throw error;
  }
}
