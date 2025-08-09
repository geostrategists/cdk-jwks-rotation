import {
  GetObjectCommand,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import {
  GetSecretValueCommand,
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
      minKeyCleanupGracePeriodSeconds: 21600,
      keySpec: { algorithm: "RS256" },
    })),
  };
});

import { cleanupExpiredKeys } from "../../src/lambda/cleanup-expired-keys";

const s3Mock = mockClient(S3Client);
const secretsManagerMock = mockClient(SecretsManagerClient);
const mockedS3Client: S3Client = s3Mock as unknown as S3Client;
const mockedSecretsManagerClient: SecretsManagerClient =
  secretsManagerMock as unknown as SecretsManagerClient;

describe("Cleanup Expired Keys", () => {
  beforeEach(() => {
    process.env.BUCKET_NAME = "test-bucket";
    process.env.BUCKET_PATH = ".well-known/jwks.json";
    process.env.MIN_ACTIVATION_GRACE_PERIOD_SECONDS = "604800";
    process.env.MAX_TOKEN_VALIDITY_DURATION_SECONDS = "3600";
    process.env.KEY_SPEC = '{"algorithm":"RS256"}';
    s3Mock.reset();
    secretsManagerMock.reset();
    vi.clearAllMocks();
    process.env.MIN_KEY_CLEANUP_GRACE_PERIOD_SECONDS = "21600";
  });

  it("should remove expired keys from JWKS", async () => {
    const currentTime = Date.now();
    const expiredTime = new Date(currentTime - 100000000).toISOString();

    secretsManagerMock
      .on(GetSecretValueCommand, {
        SecretId: "test-secret-arn",
        VersionStage: "AWSCURRENT",
      })
      .resolves({
        SecretString: JSON.stringify({
          privateKey: "current-private-key",
          kid: "current-kid",
          alg: "RS256",
          createdAt: new Date().toISOString(),
          activatedAt: expiredTime,
          publicJwk: { kty: "RSA" },
        }),
        VersionId: "current-version-id",
        VersionStages: ["AWSCURRENT"],
      });

    secretsManagerMock
      .on(GetSecretValueCommand, {
        SecretId: "test-secret-arn",
        VersionStage: "NEXT",
      })
      .resolves({
        SecretString: JSON.stringify({
          privateKey: "next-private-key",
          kid: "next-kid",
          alg: "RS256",
          createdAt: new Date().toISOString(),
          publicJwk: { kty: "RSA" },
        }),
        VersionId: "next-version-id",
        VersionStages: ["NEXT"],
      });

    secretsManagerMock
      .on(GetSecretValueCommand, {
        SecretId: "test-secret-arn",
        VersionStage: "AWSPREVIOUS",
      })
      .resolves({
        SecretString: JSON.stringify({
          privateKey: "previous-private-key",
          kid: "previous-kid",
          alg: "RS256",
          createdAt: expiredTime,
          activatedAt: expiredTime,
          publicJwk: { kty: "RSA" },
        }),
        VersionId: "previous-version-id",
        VersionStages: ["AWSPREVIOUS"],
      });

    s3Mock.on(PutObjectCommand).resolves({});

    await cleanupExpiredKeys(
      mockedSecretsManagerClient,
      mockedS3Client,
      "test-secret-arn",
    );

    const putCalls = s3Mock.commandCalls(PutObjectCommand);
    expect(putCalls).toHaveLength(1);
    expect(putCalls[0].args[0].input).toEqual({
      Bucket: "test-bucket",
      Key: ".well-known/jwks.json",
      Body: JSON.stringify(
        {
          keys: [
            { kty: "RSA", kid: "next-kid", alg: "RS256", use: "sig" },
            { kty: "RSA", kid: "current-kid", alg: "RS256", use: "sig" },
          ],
        },
        null,
        2,
      ),
      ContentType: "application/json",
      CacheControl: "public, max-age=3600",
    });
  });

  it("should keep previous key within grace period", async () => {
    const currentTime = Date.now();
    const recentTime = new Date(currentTime - 100000).toISOString();

    secretsManagerMock
      .on(GetSecretValueCommand, {
        SecretId: "test-secret-arn",
        VersionStage: "AWSCURRENT",
      })
      .resolves({
        SecretString: JSON.stringify({
          privateKey: "current-private-key",
          kid: "current-kid",
          alg: "RS256",
          createdAt: new Date().toISOString(),
          activatedAt: recentTime,
          publicJwk: { kty: "RSA" },
        }),
        VersionId: "current-version-id",
        VersionStages: ["AWSCURRENT"],
      });

    secretsManagerMock
      .on(GetSecretValueCommand, {
        SecretId: "test-secret-arn",
        VersionStage: "NEXT",
      })
      .rejects({ name: "ResourceNotFoundException" });

    secretsManagerMock
      .on(GetSecretValueCommand, {
        SecretId: "test-secret-arn",
        VersionStage: "AWSPREVIOUS",
      })
      .resolves({
        SecretString: JSON.stringify({
          privateKey: "previous-private-key",
          kid: "previous-kid",
          alg: "RS256",
          createdAt: recentTime,
          activatedAt: recentTime,
          publicJwk: { kty: "RSA" },
        }),
        VersionId: "previous-version-id",
        VersionStages: ["AWSPREVIOUS"],
      });

    s3Mock.on(PutObjectCommand).resolves({});

    await cleanupExpiredKeys(
      mockedSecretsManagerClient,
      mockedS3Client,
      "test-secret-arn",
    );

    const putCalls = s3Mock.commandCalls(PutObjectCommand);
    expect(putCalls).toHaveLength(1);
    expect(putCalls[0].args[0].input).toEqual({
      Bucket: "test-bucket",
      Key: ".well-known/jwks.json",
      Body: JSON.stringify(
        {
          keys: [
            { kty: "RSA", kid: "current-kid", alg: "RS256", use: "sig" },
            { kty: "RSA", kid: "previous-kid", alg: "RS256", use: "sig" },
          ],
        },
        null,
        2,
      ),
      ContentType: "application/json",
      CacheControl: "public, max-age=3600",
    });
  });

  it("should handle missing current secret", async () => {
    secretsManagerMock
      .on(GetSecretValueCommand, {
        SecretId: "test-secret-arn",
        VersionStage: "AWSCURRENT",
      })
      .rejects({ name: "ResourceNotFoundException" });

    await cleanupExpiredKeys(
      mockedSecretsManagerClient,
      mockedS3Client,
      "test-secret-arn",
    );

    expect(s3Mock.commandCalls(GetObjectCommand)).toHaveLength(0);
    expect(s3Mock.commandCalls(PutObjectCommand)).toHaveLength(0);
  });

  it("should handle empty JWKS file", async () => {
    secretsManagerMock
      .on(GetSecretValueCommand, {
        SecretId: "test-secret-arn",
        VersionStage: "AWSCURRENT",
      })
      .resolves({
        SecretString: JSON.stringify({
          privateKey: "current-private-key",
          kid: "current-kid",
          alg: "RS256",
          createdAt: new Date().toISOString(),
          publicJwk: { kty: "RSA" },
        }),
        VersionId: "current-version-id",
        VersionStages: ["AWSCURRENT"],
      });

    s3Mock.on(GetObjectCommand).resolves({
      Body: {
        transformToString: () => Promise.resolve(JSON.stringify({ keys: [] })),
      } as any,
    });

    await cleanupExpiredKeys(
      mockedSecretsManagerClient,
      mockedS3Client,
      "test-secret-arn",
    );

    expect(s3Mock.commandCalls(PutObjectCommand)).toHaveLength(1);
  });

  it("should handle S3 errors", async () => {
    secretsManagerMock
      .on(GetSecretValueCommand, {
        SecretId: "test-secret-arn",
        VersionStage: "AWSCURRENT",
      })
      .resolves({
        SecretString: JSON.stringify({
          privateKey: "current-private-key",
          kid: "current-kid",
          alg: "RS256",
          createdAt: new Date().toISOString(),
          publicJwk: { kty: "RSA" },
        }),
        VersionId: "current-version-id",
        VersionStages: ["AWSCURRENT"],
      });

    s3Mock.on(PutObjectCommand).rejects(new Error("S3 Error"));

    await expect(
      cleanupExpiredKeys(
        mockedSecretsManagerClient,
        mockedS3Client,
        "test-secret-arn",
      ),
    ).rejects.toThrow("S3 Error");
  });
});
