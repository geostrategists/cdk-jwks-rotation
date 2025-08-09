import {
  GetObjectCommand,
  PutObjectCommand,
  type S3Client,
} from "@aws-sdk/client-s3";
import {
  GetSecretValueCommand,
  type GetSecretValueCommandInput,
  PutSecretValueCommand,
  type PutSecretValueCommandInput,
  type SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";
import type { JSONWebKeySet, JWK } from "jose";
import type { KeySpec } from "../jwks-rotation";
import type { SecretValue } from "./types";

export interface EnvironmentConfig {
  bucketName: string;
  bucketPath: string;
  minActivationGracePeriodSeconds: number;
  maxTokenValidityDurationSeconds: number;
  minKeyCleanupGracePeriodSeconds: number;
  keySpec: KeySpec;
}

export function getEnvironmentConfig(): EnvironmentConfig {
  const bucketName = process.env.BUCKET_NAME;
  const bucketPath = process.env.BUCKET_PATH;
  const minActivationGracePeriodSecondsString =
    process.env.MIN_ACTIVATION_GRACE_PERIOD_SECONDS;
  const maxTokenValidityDurationSecondsString =
    process.env.MAX_TOKEN_VALIDITY_DURATION_SECONDS;
  const minKeyCleanupGracePeriodSecondsString =
    process.env.MIN_KEY_CLEANUP_GRACE_PERIOD_SECONDS;
  const keySpecString = process.env.KEY_SPEC;

  if (!bucketName) {
    throw new Error("BUCKET_NAME environment variable is required");
  }

  if (!bucketPath) {
    throw new Error("BUCKET_PATH environment variable is required");
  }

  if (!minActivationGracePeriodSecondsString) {
    throw new Error(
      "MIN_ACTIVATION_GRACE_PERIOD_SECONDS environment variable is required",
    );
  }

  if (!maxTokenValidityDurationSecondsString) {
    throw new Error(
      "MAX_TOKEN_VALIDITY_DURATION_SECONDS environment variable is required",
    );
  }

  if (!minKeyCleanupGracePeriodSecondsString) {
    throw new Error(
      "MIN_KEY_CLEANUP_GRACE_PERIOD_SECONDS environment variable is required",
    );
  }

  if (!keySpecString) {
    throw new Error("KEY_SPEC environment variable is required");
  }

  const minActivationGracePeriodSeconds = parseInt(
    minActivationGracePeriodSecondsString,
    10,
  );
  const maxTokenValidityDurationSeconds = parseInt(
    maxTokenValidityDurationSecondsString,
    10,
  );
  const minKeyCleanupGracePeriodSeconds = parseInt(
    minKeyCleanupGracePeriodSecondsString,
    10,
  );

  if (Number.isNaN(minActivationGracePeriodSeconds)) {
    throw new Error(
      "MIN_ACTIVATION_GRACE_PERIOD_SECONDS must be a valid number",
    );
  }

  if (Number.isNaN(maxTokenValidityDurationSeconds)) {
    throw new Error(
      "MAX_TOKEN_VALIDITY_DURATION_SECONDS must be a valid number",
    );
  }

  if (Number.isNaN(minKeyCleanupGracePeriodSeconds)) {
    throw new Error(
      "MIN_KEY_CLEANUP_GRACE_PERIOD_SECONDS must be a valid number",
    );
  }

  let keySpec: KeySpec;
  try {
    keySpec = JSON.parse(keySpecString);
  } catch (_error) {
    throw new Error("Invalid KEY_SPEC environment variable");
  }

  return {
    bucketName,
    bucketPath,
    minActivationGracePeriodSeconds,
    maxTokenValidityDurationSeconds,
    minKeyCleanupGracePeriodSeconds,
    keySpec,
  };
}

export async function getSecretValue(
  client: SecretsManagerClient,
  input: GetSecretValueCommandInput,
): Promise<{
  VersionId: string;
  VersionStages: string[] | undefined;
  secretValue: SecretValue;
} | null> {
  try {
    const response = await client.send(new GetSecretValueCommand(input));

    if (!response?.SecretString) return null;

    const { VersionId, VersionStages } = response;
    if (!VersionId) {
      throw new Error("Secret version has no VersionId");
    }

    const secretValue: SecretValue = JSON.parse(response.SecretString);

    return { secretValue, VersionId, VersionStages };
  } catch (error: unknown) {
    if (error instanceof Error && error.name === "ResourceNotFoundException") {
      return null;
    }
    throw error;
  }
}

export async function putSecretValue(
  client: SecretsManagerClient,
  value: Omit<PutSecretValueCommandInput, "SecretString"> & {
    secretValue: SecretValue;
  },
): Promise<void> {
  const { secretValue: _, ...commandInput } = value;
  const command = new PutSecretValueCommand({
    ...commandInput,
    SecretString: JSON.stringify(value.secretValue),
  });

  await client.send(command);
}

export async function getJwksFromS3(
  client: S3Client,
  bucketName: string,
  key: string,
): Promise<JSONWebKeySet> {
  try {
    const command = new GetObjectCommand({
      Bucket: bucketName,
      Key: key,
    });

    const response = await client.send(command);
    const body = await response.Body?.transformToString();

    if (!body) {
      throw new Error("Empty response from S3");
    }

    return JSON.parse(body);
  } catch (error: unknown) {
    if (error instanceof Error && error.name === "NoSuchKey") {
      return { keys: [] };
    }
    throw error;
  }
}

export async function updateJwksFile(
  client: S3Client,
  bucketName: string,
  key: string,
  jwksDocument: JSONWebKeySet,
): Promise<JSONWebKeySet> {
  const command = new PutObjectCommand({
    Bucket: bucketName,
    Key: key,
    Body: JSON.stringify(jwksDocument, null, 2),
    ContentType: "application/json",
    CacheControl: "public, max-age=3600",
  });

  await client.send(command);
  return jwksDocument;
}

type JwkSource = Pick<SecretValue, "publicJwk" | "alg" | "kid" | "activatedAt">;

export interface BuildJwksOptions {
  nextSecret?: JwkSource;
  previousSecret?: JwkSource;
  currentSecret?: JwkSource;
}

export async function buildJwks(
  secretsClient: SecretsManagerClient,
  secretId: string,
  options?: BuildJwksOptions,
): Promise<JSONWebKeySet> {
  const { minKeyCleanupGracePeriodSeconds, maxTokenValidityDurationSeconds } =
    getEnvironmentConfig();

  const keys: JWK[] = [];

  const getJwk = async (
    override: JwkSource | undefined,
    versionStage: string,
  ) =>
    override ??
    (
      await getSecretValue(secretsClient, {
        SecretId: secretId,
        VersionStage: versionStage,
      })
    )?.secretValue;

  const addJwk = (jwk: JwkSource) => {
    const { publicJwk, alg, kid } = jwk;
    keys.push({ ...publicJwk, kid, alg, use: "sig" });
  };

  const next = await getJwk(options?.nextSecret, "NEXT");
  if (next) addJwk(next);

  const current = await getJwk(options?.currentSecret, "AWSCURRENT");
  if (current?.activatedAt) addJwk(current);

  const previous = await getJwk(options?.previousSecret, "AWSPREVIOUS");
  if (previous?.activatedAt) {
    const currentActivatedAgoSeconds = current?.activatedAt
      ? (Date.now() - new Date(current.activatedAt).getTime()) / 1000
      : null;

    if (
      !currentActivatedAgoSeconds ||
      currentActivatedAgoSeconds <=
        maxTokenValidityDurationSeconds + minKeyCleanupGracePeriodSeconds
    ) {
      addJwk(previous);
    }
  }

  return { keys };
}

export async function regenerateAndPublishJwks(
  secretsClient: SecretsManagerClient,
  s3Client: S3Client,
  secretId: string,
  options?: BuildJwksOptions,
): Promise<JSONWebKeySet> {
  const { bucketName, bucketPath } = getEnvironmentConfig();
  const jwks = await buildJwks(secretsClient, secretId, options);
  await updateJwksFile(s3Client, bucketName, bucketPath, jwks);
  return jwks;
}
