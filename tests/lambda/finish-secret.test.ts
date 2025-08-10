import { mockClient } from "aws-sdk-client-mock";
import { S3Client } from "@aws-sdk/client-s3";
import {
  SecretsManagerClient,
  UpdateSecretVersionStageCommand,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import { describe, it, expect, beforeEach, vi } from "vitest";

vi.mock("../../src/lambda/utils", async () => {
  const actual = await vi.importActual("../../src/lambda/utils");
  return {
    ...actual,
    getEnvironmentConfig: vi.fn(() => ({
      bucketName: "test-bucket",
      bucketPath: "/.well-known/jwks.json",
      minActivationGracePeriodSeconds: 604800,
      maxTokenValidityDurationSeconds: 3600,
      keySpec: { algorithm: "RS256" },
    })),
  };
});

import { finishSecret } from "../../src/lambda/finish-secret";

const s3Mock = mockClient(S3Client);
const secretsManagerMock = mockClient(SecretsManagerClient);
const mockedS3Client: S3Client = s3Mock as unknown as S3Client;
const mockedSecretsManagerClient: SecretsManagerClient = secretsManagerMock as unknown as SecretsManagerClient;

describe("Finish Secret", () => {
  beforeEach(() => {
    process.env.BUCKET_NAME = "test-bucket";
    process.env.BUCKET_PATH = "/.well-known/jwks.json";
    process.env.MIN_ACTIVATION_GRACE_PERIOD_SECONDS = "604800";
    process.env.MAX_TOKEN_VALIDITY_DURATION_SECONDS = "3600";
    process.env.KEY_SPEC = '{"algorithm":"RS256"}';
    process.env.MIN_KEY_CLEANUP_GRACE_PERIOD_SECONDS = "21600";

    s3Mock.reset();
    secretsManagerMock.reset();
    vi.clearAllMocks();
  });

  it("should successfully finish rotation with existing current version", async () => {
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
          publicKeyJwk: { kty: "RSA" },
        }),
        VersionId: "current-version-id",
        VersionStages: ["AWSCURRENT"],
      });

    secretsManagerMock
      .on(GetSecretValueCommand, {
        SecretId: "test-secret",
        VersionId: "test-token",
        VersionStage: "AWSPENDING",
      })
      .resolves({
        SecretString: JSON.stringify({
          privateKeyPem: "pending-private-key",
          kid: "pending-kid",
          alg: "RS256",
          createdAt: new Date().toISOString(),
          publicKeyJwk: { kty: "RSA" },
        }),
        VersionId: "test-token",
        VersionStages: ["AWSPENDING"],
      });

    secretsManagerMock.on(UpdateSecretVersionStageCommand).resolves({});

    await finishSecret(mockedSecretsManagerClient, mockedS3Client, "test-secret", "test-token");

    const updateCalls = secretsManagerMock.commandCalls(UpdateSecretVersionStageCommand);
    expect(updateCalls).toHaveLength(1);

    expect(updateCalls[0].args[0].input).toEqual({
      SecretId: "test-secret",
      VersionStage: "AWSCURRENT",
      MoveToVersionId: "test-token",
      RemoveFromVersionId: "current-version-id",
    });
  });

  it("should throw error when current version not found", async () => {
    secretsManagerMock
      .on(GetSecretValueCommand, {
        SecretId: "test-secret",
        VersionStage: "AWSCURRENT",
      })
      .rejects({ name: "ResourceNotFoundException" });

    await expect(
      finishSecret(mockedSecretsManagerClient, mockedS3Client, "test-secret", "test-token")
    ).rejects.toThrow("Current version not found");
  });

  it("should add deactivation timestamp to previous version", async () => {
    const currentSecretValue = {
      privateKeyPem: "current-private-key",
      kid: "current-kid",
      alg: "RS256",
      createdAt: new Date().toISOString(),
      publicKeyJwk: { kty: "RSA" },
    };

    secretsManagerMock
      .on(GetSecretValueCommand, {
        SecretId: "test-secret",
        VersionStage: "AWSCURRENT",
      })
      .resolves({
        SecretString: JSON.stringify(currentSecretValue),
        VersionId: "current-version-id",
        VersionStages: ["AWSCURRENT"],
      });

    secretsManagerMock
      .on(GetSecretValueCommand, {
        SecretId: "test-secret",
        VersionId: "test-token",
        VersionStage: "AWSPENDING",
      })
      .resolves({
        SecretString: JSON.stringify({
          privateKeyPem: "pending-private-key",
          kid: "pending-kid",
          alg: "RS256",
          createdAt: new Date().toISOString(),
          publicKeyJwk: { kty: "RSA" },
        }),
        VersionId: "test-token",
        VersionStages: ["AWSPENDING"],
      });

    secretsManagerMock.on(UpdateSecretVersionStageCommand).resolves({});

    await finishSecret(mockedSecretsManagerClient, mockedS3Client, "test-secret", "test-token");

    const updateCalls = secretsManagerMock.commandCalls(UpdateSecretVersionStageCommand);
    expect(updateCalls).toHaveLength(1);

    expect(updateCalls[0].args[0].input).toEqual({
      SecretId: "test-secret",
      VersionStage: "AWSCURRENT",
      MoveToVersionId: "test-token",
      RemoveFromVersionId: "current-version-id",
    });
  });

  it("should handle secrets manager errors", async () => {
    secretsManagerMock
      .on(GetSecretValueCommand)
      .rejects(new Error("SecretsManager Error"));

    await expect(
      finishSecret(mockedSecretsManagerClient, mockedS3Client, "test-secret", "test-token")
    ).rejects.toThrow("SecretsManager Error");
  });

  it("should handle update version stage errors", async () => {
    secretsManagerMock
      .on(GetSecretValueCommand)
      .resolves({
        SecretString: JSON.stringify({
          privateKeyPem: "current-private-key",
          kid: "current-kid",
          alg: "RS256",
          createdAt: new Date().toISOString(),
          publicKeyJwk: { kty: "RSA" },
        }),
        VersionId: "current-version-id",
        VersionStages: ["AWSCURRENT"],
      });

    secretsManagerMock
      .on(UpdateSecretVersionStageCommand)
      .rejects(new Error("Update Error"));

    await expect(
      finishSecret(mockedSecretsManagerClient, mockedS3Client, "test-secret", "test-token")
    ).rejects.toThrow("Update Error");
  });
});
