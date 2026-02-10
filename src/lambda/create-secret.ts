import type { S3Client } from "@aws-sdk/client-s3";
import type { SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import { exportJWK, exportPKCS8, type GenerateKeyPairResult, generateKeyPair } from "jose";
import { nanoid } from "nanoid";
import type { KeySpec } from "../jwks-rotation";
import type { SecretValue } from "./types";
import {
  getEnvironmentConfig,
  getSecretValue,
  putSecretValue,
  regenerateAndPublishJwks,
} from "./utils";

export async function createSecret(
  secretsClient: SecretsManagerClient,
  s3Client: S3Client,
  secretId: string,
  token: string,
): Promise<void> {
  console.log("Starting createSecret step");

  const { minActivationGracePeriodSeconds, keySpec } = getEnvironmentConfig();

  let nextKeyData: SecretValue | undefined;

  const currentSecret = await getSecretValue(secretsClient, {
    SecretId: secretId,
    VersionStage: "AWSCURRENT",
  });

  const nextSecret = await getSecretValue(secretsClient, {
    SecretId: secretId,
    VersionStage: "NEXT",
  });

  if (!nextSecret) {
    if (currentSecret?.secretValue.activatedAt) {
      console.log(
        "No NEXT key exists but current key found. Creating NEXT key and aborting rotation.",
      );
      const newNextKeyPair = await generateJwksKeyPair(keySpec);

      await putSecretValue(secretsClient, {
        SecretId: secretId,
        ClientRequestToken: `next-key-${currentSecret.VersionId}`,
        VersionStages: ["NEXT"],
        secretValue: newNextKeyPair.secretValue,
      });
      console.log("Created NEXT key and aborting rotation");

      await regenerateAndPublishJwks(secretsClient, s3Client, secretId, {
        currentSecret: currentSecret?.secretValue,
        nextSecret: newNextKeyPair.secretValue,
      });

      throw new Error("Created NEXT key. Aborting rotation as requested.");
    }

    console.log(
      "No current secret or current in initial state. Creating key for immediate activation.",
    );
    const keyPair = await generateJwksKeyPair(keySpec);
    nextKeyData = keyPair.secretValue;
  } else {
    const nextSecretValue = nextSecret.secretValue;
    const creationDate = new Date(nextSecretValue.createdAt);

    const ageInSeconds = (Date.now() - creationDate.getTime()) / 1000;

    if (ageInSeconds < minActivationGracePeriodSeconds) {
      throw new Error(
        `Next key is too new (${ageInSeconds}s < ${minActivationGracePeriodSeconds}s). Aborting rotation.`,
      );
    }

    nextKeyData = nextSecretValue;
    console.log("Reusing existing NEXT key for AWSPENDING");
  }

  const pendingSecretValue: SecretValue = {
    ...nextKeyData,
    activatedAt: new Date().toISOString(),
  };

  await putSecretValue(secretsClient, {
    SecretId: secretId,
    ClientRequestToken: token,
    VersionStages: ["AWSPENDING"],
    secretValue: pendingSecretValue,
  });
  console.log(`Stored key ${pendingSecretValue.kid} in AWSPENDING version`);

  const newNextKeyPair = await generateJwksKeyPair(keySpec);

  await putSecretValue(secretsClient, {
    SecretId: secretId,
    ClientRequestToken: `next-key-${token}`,
    VersionStages: ["NEXT"],
    secretValue: newNextKeyPair.secretValue,
  });
  console.log(`Stored next key ${newNextKeyPair.secretValue.kid} in NEXT version`);

  // we need to build the JWKS file now so that testSecret can use it
  await regenerateAndPublishJwks(secretsClient, s3Client, secretId, {
    previousSecret: currentSecret?.secretValue,
    currentSecret: pendingSecretValue,
    nextSecret: newNextKeyPair.secretValue,
  });

  console.log("Updated JWKS file by regenerating from stages");
}

async function generateJwksKeyPair(keySpec: KeySpec): Promise<{
  secretValue: SecretValue;
}> {
  const { algorithm, crv, modulusLength } = keySpec;

  let keyPair: GenerateKeyPairResult;

  if (algorithm.startsWith("RS") || algorithm.startsWith("PS")) {
    keyPair = await generateKeyPair(algorithm, {
      modulusLength: modulusLength || 2048,
      extractable: true,
    });
  } else if (algorithm.startsWith("ES")) {
    keyPair = await generateKeyPair(algorithm, {
      crv,
      extractable: true,
    });
  } else {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }

  const kid = nanoid();
  const alg = algorithm;

  const privateKeyPem = await exportPKCS8(keyPair.privateKey);
  const publicKeyJwk = await exportJWK(keyPair.publicKey);

  const secretValue: SecretValue = {
    privateKeyPem,
    publicKeyJwk,
    kid,
    alg,
    createdAt: new Date().toISOString(),
  };

  return {
    secretValue,
  };
}
