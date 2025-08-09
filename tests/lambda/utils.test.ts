import {
  GetObjectCommand,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import {
  GetSecretValueCommand,
  PutSecretValueCommand,
  SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";
import { mockClient } from "aws-sdk-client-mock";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  getEnvironmentConfig,
  getJwksFromS3,
  getSecretValue,
  putSecretValue,
  updateJwksFile,
} from "../../src/lambda/utils";

const s3Mock = mockClient(S3Client);
const secretsManagerMock = mockClient(SecretsManagerClient);
const mockedS3Client: S3Client = s3Mock as unknown as S3Client;
const mockedSecretsManagerClient: SecretsManagerClient =
  secretsManagerMock as unknown as SecretsManagerClient;

describe("Utils", () => {
  beforeEach(() => {
    s3Mock.reset();
    secretsManagerMock.reset();
    vi.clearAllMocks();
    delete process.env.BUCKET_NAME;
    delete process.env.BUCKET_PATH;
    delete process.env.MIN_ACTIVATION_GRACE_PERIOD_SECONDS;
    delete process.env.MAX_TOKEN_VALIDITY_DURATION_SECONDS;
    delete process.env.KEY_SPEC;
    process.env.MIN_KEY_CLEANUP_GRACE_PERIOD_SECONDS = "21600";
  });

  describe("getEnvironmentConfig", () => {
    it("should return valid config when all env vars are set", () => {
      process.env.BUCKET_NAME = "test-bucket";
      process.env.BUCKET_PATH = ".well-known/jwks.json";
      process.env.MIN_ACTIVATION_GRACE_PERIOD_SECONDS = "604800";
      process.env.MAX_TOKEN_VALIDITY_DURATION_SECONDS = "3600";
      process.env.KEY_SPEC = JSON.stringify({ algorithm: "RS256" });

      const config = getEnvironmentConfig();

      expect(config).toEqual({
        bucketName: "test-bucket",
        bucketPath: ".well-known/jwks.json",
        minActivationGracePeriodSeconds: 604800,
        maxTokenValidityDurationSeconds: 3600,
        minKeyCleanupGracePeriodSeconds: 21600,
        keySpec: { algorithm: "RS256" },
      });
    });

    it("should throw error when BUCKET_NAME is missing", () => {
      process.env.BUCKET_PATH = ".well-known/jwks.json";
      process.env.MIN_ACTIVATION_GRACE_PERIOD_SECONDS = "604800";
      process.env.MAX_TOKEN_VALIDITY_DURATION_SECONDS = "3600";
      process.env.KEY_SPEC = JSON.stringify({ algorithm: "RS256" });

      expect(() => getEnvironmentConfig()).toThrow(
        "BUCKET_NAME environment variable is required",
      );
    });

    it("should throw error when BUCKET_PATH is missing", () => {
      process.env.BUCKET_NAME = "test-bucket";
      process.env.MIN_ACTIVATION_GRACE_PERIOD_SECONDS = "604800";
      process.env.MAX_TOKEN_VALIDITY_DURATION_SECONDS = "3600";
      process.env.KEY_SPEC = JSON.stringify({ algorithm: "RS256" });

      expect(() => getEnvironmentConfig()).toThrow(
        "BUCKET_PATH environment variable is required",
      );
    });

    it("should throw error when MIN_ACTIVATION_GRACE_PERIOD_SECONDS is invalid", () => {
      process.env.BUCKET_NAME = "test-bucket";
      process.env.BUCKET_PATH = ".well-known/jwks.json";
      process.env.MIN_ACTIVATION_GRACE_PERIOD_SECONDS = "invalid";
      process.env.MAX_TOKEN_VALIDITY_DURATION_SECONDS = "3600";
      process.env.KEY_SPEC = JSON.stringify({ algorithm: "RS256" });

      expect(() => getEnvironmentConfig()).toThrow(
        "MIN_ACTIVATION_GRACE_PERIOD_SECONDS must be a valid number",
      );
    });

    it("should throw error when KEY_SPEC is invalid JSON", () => {
      process.env.BUCKET_NAME = "test-bucket";
      process.env.BUCKET_PATH = ".well-known/jwks.json";
      process.env.MIN_ACTIVATION_GRACE_PERIOD_SECONDS = "604800";
      process.env.MAX_TOKEN_VALIDITY_DURATION_SECONDS = "3600";
      process.env.KEY_SPEC = "invalid-json";

      expect(() => getEnvironmentConfig()).toThrow(
        "Invalid KEY_SPEC environment variable",
      );
    });
  });

  describe("getSecretValue", () => {
    it("should return secret value when found", async () => {
      const mockSecretValue = {
        privateKey: "test-private-key",
        kid: "test-kid",
        alg: "RS256",
        createdAt: new Date().toISOString(),
        publicJwk: { kty: "RSA" },
      };

      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(mockSecretValue),
        VersionId: "version-123",
        VersionStages: ["AWSCURRENT"],
      });

      const result = await getSecretValue(secretsManagerMock as any, {
        SecretId: "test-secret",
      });

      expect(result).toEqual({
        secretValue: mockSecretValue,
        VersionId: "version-123",
        VersionStages: ["AWSCURRENT"],
      });
    });

    it("should return null when secret not found", async () => {
      secretsManagerMock
        .on(GetSecretValueCommand)
        .rejects({ name: "ResourceNotFoundException" });

      const result = await getSecretValue(secretsManagerMock as any, {
        SecretId: "test-secret",
      });

      expect(result).toBeNull();
    });

    it("should throw error when VersionId is missing", async () => {
      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify({ test: "value" }),
        VersionStages: ["AWSCURRENT"],
      });

      await expect(
        getSecretValue(mockedSecretsManagerClient, { SecretId: "test-secret" }),
      ).rejects.toThrow("Secret version has no VersionId");
    });

    it("should throw error for other AWS errors", async () => {
      secretsManagerMock
        .on(GetSecretValueCommand)
        .rejects(new Error("AWS Error"));

      await expect(
        getSecretValue(secretsManagerMock as any, { SecretId: "test-secret" }),
      ).rejects.toThrow("AWS Error");
    });
  });

  describe("putSecretValue", () => {
    it("should put secret value successfully", async () => {
      const mockSecretValue = {
        privateKey: "test-private-key",
        kid: "test-kid",
        alg: "RS256",
        createdAt: new Date().toISOString(),
        publicJwk: { kty: "RSA" },
      };

      secretsManagerMock.on(PutSecretValueCommand).resolves({});

      await putSecretValue(secretsManagerMock as any, {
        SecretId: "test-secret",
        ClientRequestToken: "test-token",
        secretValue: mockSecretValue,
      });

      expect(
        secretsManagerMock.commandCalls(PutSecretValueCommand),
      ).toHaveLength(1);
      expect(
        secretsManagerMock.commandCalls(PutSecretValueCommand)[0].args[0].input,
      ).toEqual({
        SecretId: "test-secret",
        ClientRequestToken: "test-token",
        SecretString: JSON.stringify(mockSecretValue),
      });
    });

    it("should handle AWS errors", async () => {
      secretsManagerMock
        .on(PutSecretValueCommand)
        .rejects(new Error("AWS Error"));

      await expect(
        putSecretValue(secretsManagerMock as any, {
          SecretId: "test-secret",
          ClientRequestToken: "test-token",
          secretValue: { test: "value" } as any,
        }),
      ).rejects.toThrow("AWS Error");
    });
  });

  describe("getJwksFromS3", () => {
    it("should return JWKS when file exists", async () => {
      const mockJwks = {
        keys: [{ kid: "test-kid", kty: "RSA", alg: "RS256" }],
      };

      s3Mock.on(GetObjectCommand).resolves({
        Body: {
          transformToString: () => Promise.resolve(JSON.stringify(mockJwks)),
        } as any,
      });

      const result = await getJwksFromS3(
        mockedS3Client,
        "test-bucket",
        ".well-known/jwks.json",
      );

      expect(result).toEqual(mockJwks);
      expect(s3Mock.commandCalls(GetObjectCommand)).toHaveLength(1);
      expect(s3Mock.commandCalls(GetObjectCommand)[0].args[0].input).toEqual({
        Bucket: "test-bucket",
        Key: ".well-known/jwks.json",
      });
    });

    it("should return empty JWKS when file not found", async () => {
      s3Mock.on(GetObjectCommand).rejects({ name: "NoSuchKey" });

      const result = await getJwksFromS3(
        mockedS3Client,
        "test-bucket",
        ".well-known/jwks.json",
      );

      expect(result).toEqual({ keys: [] });
    });

    it("should handle empty response body", async () => {
      s3Mock.on(GetObjectCommand).resolves({
        Body: {
          transformToString: () => Promise.resolve(""),
        } as any,
      });

      await expect(
        getJwksFromS3(mockedS3Client, "test-bucket", ".well-known/jwks.json"),
      ).rejects.toThrow("Empty response from S3");
    });

    it("should handle other S3 errors", async () => {
      s3Mock.on(GetObjectCommand).rejects(new Error("S3 Error"));

      await expect(
        getJwksFromS3(mockedS3Client, "test-bucket", ".well-known/jwks.json"),
      ).rejects.toThrow("S3 Error");
    });
  });

  describe("updateJwksFile", () => {
    it("should update JWKS file successfully", async () => {
      const mockJwks = {
        keys: [{ kid: "test-kid", kty: "RSA", alg: "RS256" }],
      };

      s3Mock.on(PutObjectCommand).resolves({});

      const result = await updateJwksFile(
        mockedS3Client,
        "test-bucket",
        ".well-known/jwks.json",
        mockJwks,
      );

      expect(result).toEqual(mockJwks);
      expect(s3Mock.commandCalls(PutObjectCommand)).toHaveLength(1);
      expect(s3Mock.commandCalls(PutObjectCommand)[0].args[0].input).toEqual({
        Bucket: "test-bucket",
        Key: ".well-known/jwks.json",
        Body: JSON.stringify(mockJwks, null, 2),
        ContentType: "application/json",
        CacheControl: "public, max-age=3600",
      });
    });

    it("should handle paths without leading slash", async () => {
      const mockJwks = { keys: [] };

      s3Mock.on(PutObjectCommand).resolves({});

      await updateJwksFile(
        mockedS3Client,
        "test-bucket",
        "jwks.json",
        mockJwks,
      );

      expect(s3Mock.commandCalls(PutObjectCommand)).toHaveLength(1);
      expect(s3Mock.commandCalls(PutObjectCommand)[0].args[0].input).toEqual({
        Bucket: "test-bucket",
        Key: "jwks.json",
        Body: JSON.stringify(mockJwks, null, 2),
        ContentType: "application/json",
        CacheControl: "public, max-age=3600",
      });
    });

    it("should handle S3 errors", async () => {
      s3Mock.on(PutObjectCommand).rejects(new Error("S3 Error"));

      await expect(
        updateJwksFile(mockedS3Client, "test-bucket", ".well-known/jwks.json", {
          keys: [],
        }),
      ).rejects.toThrow("S3 Error");
    });
  });
});
