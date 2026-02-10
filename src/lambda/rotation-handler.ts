import { S3Client } from "@aws-sdk/client-s3";
import { SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import type { SecretsManagerRotationEvent } from "aws-lambda";
import { cleanupExpiredKeys } from "./cleanup-expired-keys";
import { createSecret } from "./create-secret";
import { finishSecret } from "./finish-secret";
import { testSecret } from "./test-secret";

const secretsClient = new SecretsManagerClient({});
const s3Client = new S3Client({});

export interface CleanupEvent {
  action: "cleanup";
  secretArn: string;
}

export type LambdaEvent = SecretsManagerRotationEvent | CleanupEvent;

export async function handler(event: LambdaEvent): Promise<void> {
  console.log("Received event:", JSON.stringify(event, null, 2));

  if ("action" in event) {
    if (event.action === "cleanup") {
      await handleCleanupEvent(event);
      return;
    }
    throw new Error("Invalid event action");
  }

  await handleRotationEvent(event as SecretsManagerRotationEvent);
}

async function handleRotationEvent(event: SecretsManagerRotationEvent): Promise<void> {
  const { Step, SecretId, ClientRequestToken: Token } = event;

  try {
    switch (Step) {
      case "createSecret":
        await createSecret(secretsClient, s3Client, SecretId, Token);
        break;
      case "setSecret":
        console.log("setSecret step - no action needed for JWKS rotation");
        break;
      case "testSecret":
        await testSecret(secretsClient, s3Client, SecretId, Token);
        break;
      case "finishSecret":
        await finishSecret(secretsClient, s3Client, SecretId, Token);
        break;
      default:
        throw new Error(`Invalid step: ${Step}`);
    }

    console.log(`Successfully completed step: ${Step}`);
  } catch (error) {
    console.error(`Error in step ${Step}:`, error);
    throw error;
  }
}

async function handleCleanupEvent(event: CleanupEvent): Promise<void> {
  try {
    await cleanupExpiredKeys(secretsClient, s3Client, event.secretArn);
    console.log("Successfully completed cleanup");
  } catch (error) {
    console.error("Error in cleanup:", error);
    throw error;
  }
}
