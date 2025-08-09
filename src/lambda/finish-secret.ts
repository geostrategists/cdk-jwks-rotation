import type { S3Client } from "@aws-sdk/client-s3";
import {
  type SecretsManagerClient,
  UpdateSecretVersionStageCommand,
} from "@aws-sdk/client-secrets-manager";
import { getSecretValue, regenerateAndPublishJwks } from "./utils";

export async function finishSecret(
  secretsClient: SecretsManagerClient,
  s3Client: S3Client,
  secretId: string,
  token: string,
): Promise<void> {
  console.log("Starting finishSecret step");

  const currentSecret = await getSecretValue(secretsClient, {
    SecretId: secretId,
    VersionStage: "AWSCURRENT",
  });
  if (!currentSecret) {
    throw new Error("Current version not found");
  }

  const pendingSecret = await getSecretValue(secretsClient, {
    SecretId: secretId,
    VersionId: token,
    VersionStage: "AWSPENDING",
  });
  if (!pendingSecret) {
    throw new Error("Pending version not found");
  }

  console.log("Moving AWSPENDING to AWSCURRENT");
  await secretsClient.send(
    new UpdateSecretVersionStageCommand({
      SecretId: secretId,
      VersionStage: "AWSCURRENT",
      MoveToVersionId: pendingSecret.VersionId,
      RemoveFromVersionId: currentSecret.VersionId,
    }),
  );

  await regenerateAndPublishJwks(secretsClient, s3Client, secretId, {
    currentSecret: pendingSecret.secretValue,
    previousSecret: currentSecret.secretValue,
  });

  console.log("finishSecret completed successfully");
}
