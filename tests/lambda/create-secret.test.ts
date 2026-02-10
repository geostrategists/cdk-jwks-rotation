import { GetObjectCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import {
  GetSecretValueCommand,
  PutSecretValueCommand,
  SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";
import { mockClient } from "aws-sdk-client-mock";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/lambda/utils", async () => {
  const actual = await vi.importActual("../../src/lambda/utils");
  return {
    ...actual,
    getEnvironmentConfig: vi.fn(() => ({
      bucketName: "test-bucket",
      bucketPath: ".well-known/jwks.json",
      minActivationGracePeriodSeconds: 604800,
      maxTokenValidityDurationSeconds: 3600,
      keySpec: { algorithm: "RS256" },
    })),
  };
});

import { createSecret } from "../../src/lambda/create-secret";

const s3Mock = mockClient(S3Client);
const secretsManagerMock = mockClient(SecretsManagerClient);
const mockedS3Client: S3Client = s3Mock as unknown as S3Client;
const mockedSecretsManagerClient: SecretsManagerClient =
  secretsManagerMock as unknown as SecretsManagerClient;

describe("Create Secret", () => {
  beforeEach(() => {
    process.env.BUCKET_NAME = "test-bucket";
    process.env.BUCKET_PATH = ".well-known/jwks.json";
    process.env.MIN_ACTIVATION_GRACE_PERIOD_SECONDS = "604800";
    process.env.MAX_TOKEN_VALIDITY_DURATION_SECONDS = "3600";
    process.env.KEY_SPEC = '{"algorithm":"RS256"}';
    process.env.MIN_KEY_CLEANUP_GRACE_PERIOD_SECONDS = "21600";

    s3Mock.reset();
    secretsManagerMock.reset();
    vi.clearAllMocks();
  });

  it("should create a new key when no NEXT key exists", async () => {
    secretsManagerMock
      .on(GetSecretValueCommand, {
        SecretId: "test-secret",
        VersionStage: "NEXT",
      })
      .rejects({ name: "ResourceNotFoundException" });

    secretsManagerMock.on(PutSecretValueCommand).resolves({
      VersionId: "new-version-id",
    });

    s3Mock.on(GetObjectCommand).rejects({ name: "NoSuchKey" });
    s3Mock.on(PutObjectCommand).resolves({});

    await createSecret(mockedSecretsManagerClient, mockedS3Client, "test-secret", "test-token");

    expect(secretsManagerMock.commandCalls(PutSecretValueCommand)).toHaveLength(2);
  });

  it("should reuse existing NEXT key if it's old enough", async () => {
    const oldDate = new Date(Date.now() - 1000000000).toISOString();

    secretsManagerMock
      .on(GetSecretValueCommand, {
        SecretId: "test-secret",
        VersionStage: "NEXT",
      })
      .resolves({
        SecretString: JSON.stringify({
          privateKeyPem: "existing-private-key",
          kid: "existing-kid",
          alg: "RS256",
          createdAt: oldDate,
          publicKeyJwk: { kty: "RSA" },
        }),
        VersionId: "existing-version-id",
        VersionStages: ["NEXT"],
      });

    secretsManagerMock.on(PutSecretValueCommand).resolves({
      VersionId: "new-version-id",
    });

    s3Mock.on(GetObjectCommand).resolves({
      Body: {
        transformToString: () => Promise.resolve(JSON.stringify({ keys: [] })),
      } as any,
    });
    s3Mock.on(PutObjectCommand).resolves({});

    await createSecret(mockedSecretsManagerClient, mockedS3Client, "test-secret", "test-token");

    expect(secretsManagerMock.commandCalls(PutSecretValueCommand)).toHaveLength(2);
  });

  it("should abort rotation if NEXT key is too new", async () => {
    const recentDate = new Date().toISOString();

    secretsManagerMock
      .on(GetSecretValueCommand, {
        SecretId: "test-secret",
        VersionStage: "NEXT",
      })
      .resolves({
        SecretString: JSON.stringify({
          privateKeyPem: "recent-private-key",
          kid: "recent-kid",
          alg: "RS256",
          createdAt: recentDate,
          publicKeyJwk: { kty: "RSA" },
        }),
        VersionId: "recent-version-id",
        VersionStages: ["NEXT"],
      });

    await expect(
      createSecret(secretsManagerMock as any, s3Mock as any, "test-secret", "test-token"),
    ).rejects.toThrow("Next key is too new");

    expect(secretsManagerMock.commandCalls(PutSecretValueCommand)).toHaveLength(0);
  });

  it("should handle S3 errors gracefully", async () => {
    secretsManagerMock.on(GetSecretValueCommand).rejects({ name: "ResourceNotFoundException" });

    secretsManagerMock.on(PutSecretValueCommand).resolves({
      VersionId: "new-version-id",
    });

    s3Mock.on(GetObjectCommand).rejects(new Error("S3 Error"));
    s3Mock.on(PutObjectCommand).resolves({});

    await createSecret(mockedSecretsManagerClient, mockedS3Client, "test-secret", "test-token");
  });

  it("should handle secrets manager errors", async () => {
    secretsManagerMock.on(GetSecretValueCommand).rejects(new Error("SecretsManager Error"));

    await expect(
      createSecret(secretsManagerMock as any, s3Mock as any, "test-secret", "test-token"),
    ).rejects.toThrow("SecretsManager Error");
  });

  it("should generate ES256 keys correctly", async () => {
    secretsManagerMock.on(GetSecretValueCommand).rejects({ name: "ResourceNotFoundException" });

    secretsManagerMock.on(PutSecretValueCommand).resolves({
      VersionId: "new-version-id",
    });

    s3Mock.on(GetObjectCommand).rejects({ name: "NoSuchKey" });
    s3Mock.on(PutObjectCommand).resolves({});

    await createSecret(mockedSecretsManagerClient, mockedS3Client, "test-secret", "test-token");

    expect(secretsManagerMock.commandCalls(PutSecretValueCommand)).toHaveLength(2);
  });

  it("should create NEXT key and abort when no NEXT exists but current exists", async () => {
    secretsManagerMock
      .on(GetSecretValueCommand, {
        SecretId: "test-secret",
        VersionStage: "NEXT",
      })
      .rejects({ name: "ResourceNotFoundException" });

    secretsManagerMock
      .on(GetSecretValueCommand, {
        SecretId: "test-secret",
        VersionStage: "AWSCURRENT",
      })
      .resolves({
        SecretString: JSON.stringify({
          privateKeyPem: "current-private-key",
          kid: "current-kid",
          alg: "RS256",
          createdAt: new Date().toISOString(),
          activatedAt: new Date().toISOString(),
          publicKeyJwk: { kty: "RSA" },
        }),
        VersionId: "current-version-id",
        VersionStages: ["AWSCURRENT"],
      });

    secretsManagerMock.on(PutSecretValueCommand).resolves({
      VersionId: "new-version-id",
    });

    s3Mock.on(GetObjectCommand).resolves({
      Body: {
        transformToString: () => Promise.resolve(JSON.stringify({ keys: [] })),
      } as any,
    });
    s3Mock.on(PutObjectCommand).resolves({});

    await expect(
      createSecret(secretsManagerMock as any, s3Mock as any, "test-secret", "test-token"),
    ).rejects.toThrow("Created NEXT key. Aborting rotation as requested.");

    const putCalls = secretsManagerMock.commandCalls(PutSecretValueCommand);
    expect(putCalls).toHaveLength(1);
    expect(putCalls[0].args[0].input).toMatchObject({
      SecretId: "test-secret",
      ClientRequestToken: "next-key-current-version-id",
      VersionStages: ["NEXT"],
    });
  });

  it("should create key for immediate activation when no current secret exists", async () => {
    secretsManagerMock
      .on(GetSecretValueCommand, {
        SecretId: "test-secret",
        VersionStage: "NEXT",
      })
      .rejects({ name: "ResourceNotFoundException" });

    secretsManagerMock
      .on(GetSecretValueCommand, {
        SecretId: "test-secret",
        VersionStage: "AWSCURRENT",
      })
      .rejects({ name: "ResourceNotFoundException" });

    secretsManagerMock.on(PutSecretValueCommand).resolves({
      VersionId: "new-version-id",
    });

    s3Mock.on(GetObjectCommand).resolves({
      Body: {
        transformToString: () => Promise.resolve(JSON.stringify({ keys: [] })),
      } as any,
    });
    s3Mock.on(PutObjectCommand).resolves({});

    await createSecret(mockedSecretsManagerClient, mockedS3Client, "test-secret", "test-token");

    expect(secretsManagerMock.commandCalls(PutSecretValueCommand)).toHaveLength(2);
  });

  it("should create key for immediate activation when current secret is in initial state", async () => {
    secretsManagerMock
      .on(GetSecretValueCommand, {
        SecretId: "test-secret",
        VersionStage: "NEXT",
      })
      .rejects({ name: "ResourceNotFoundException" });

    secretsManagerMock
      .on(GetSecretValueCommand, {
        SecretId: "test-secret",
        VersionStage: "AWSCURRENT",
      })
      .resolves({
        SecretString: JSON.stringify({
          privateKeyPem: "initial-private-key",
          kid: "initial-kid",
          alg: "RS256",
          createdAt: new Date().toISOString(),
          publicKeyJwk: { kty: "RSA" },
        }),
        VersionId: "initial-version-id",
        VersionStages: ["AWSCURRENT"],
      });

    secretsManagerMock.on(PutSecretValueCommand).resolves({
      VersionId: "new-version-id",
    });

    s3Mock.on(GetObjectCommand).resolves({
      Body: {
        transformToString: () => Promise.resolve(JSON.stringify({ keys: [] })),
      } as any,
    });
    s3Mock.on(PutObjectCommand).resolves({});

    await createSecret(mockedSecretsManagerClient, mockedS3Client, "test-secret", "test-token");

    expect(secretsManagerMock.commandCalls(PutSecretValueCommand)).toHaveLength(2);
  });
});
