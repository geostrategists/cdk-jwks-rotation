import { mockClient } from "aws-sdk-client-mock";
import { S3Client } from "@aws-sdk/client-s3";
import { SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { handler } from "../../src/lambda/rotation-handler";
import type { SecretsManagerRotationEvent } from "aws-lambda";
import type { CleanupEvent } from "../../src/lambda/rotation-handler";

const s3Mock = mockClient(S3Client);
const secretsManagerMock = mockClient(SecretsManagerClient);

vi.mock("../../src/lambda/create-secret", () => ({
  createSecret: vi.fn(),
}));
vi.mock("../../src/lambda/test-secret", () => ({
  testSecret: vi.fn(),
}));
vi.mock("../../src/lambda/finish-secret", () => ({
  finishSecret: vi.fn(),
}));
vi.mock("../../src/lambda/cleanup-expired-keys", () => ({
  cleanupExpiredKeys: vi.fn(),
}));

const { createSecret } = await import("../../src/lambda/create-secret");
const { testSecret } = await import("../../src/lambda/test-secret");
const { finishSecret } = await import("../../src/lambda/finish-secret");
const { cleanupExpiredKeys } = await import("../../src/lambda/cleanup-expired-keys");

describe("Rotation Handler", () => {
  beforeEach(() => {
    s3Mock.reset();
    secretsManagerMock.reset();
    vi.clearAllMocks();
  });

  describe("rotation events", () => {
    it("should handle createSecret step", async () => {
      const event: SecretsManagerRotationEvent = {
        Step: "createSecret",
        SecretId: "test-secret",
        ClientRequestToken: "test-token",
      };

      await handler(event);

      expect(createSecret).toHaveBeenCalledWith(
        expect.any(SecretsManagerClient),
        expect.any(S3Client),
        "test-secret",
        "test-token"
      );
    });

    it("should handle setSecret step", async () => {
      const event: SecretsManagerRotationEvent = {
        Step: "setSecret",
        SecretId: "test-secret",
        ClientRequestToken: "test-token",
      };

      await handler(event);

      expect(createSecret).not.toHaveBeenCalled();
      expect(testSecret).not.toHaveBeenCalled();
      expect(finishSecret).not.toHaveBeenCalled();
    });

    it("should handle testSecret step", async () => {
      const event: SecretsManagerRotationEvent = {
        Step: "testSecret",
        SecretId: "test-secret",
        ClientRequestToken: "test-token",
      };

      await handler(event);

      expect(testSecret).toHaveBeenCalledWith(
        expect.any(SecretsManagerClient),
        expect.any(S3Client),
        "test-secret",
        "test-token"
      );
    });

    it("should handle finishSecret step", async () => {
      const event: SecretsManagerRotationEvent = {
        Step: "finishSecret",
        SecretId: "test-secret",
        ClientRequestToken: "test-token",
      };

      await handler(event);

      expect(finishSecret).toHaveBeenCalledWith(
        expect.any(SecretsManagerClient),
        expect.any(S3Client),
        "test-secret",
        "test-token"
      );
    });

    it("should throw error for invalid step", async () => {
      const event = {
        Step: "invalidStep",
        SecretId: "test-secret",
        ClientRequestToken: "test-token",
      } as any;

      await expect(handler(event)).rejects.toThrow("Invalid step: invalidStep");
    });

    it("should handle errors in rotation steps", async () => {
      const event: SecretsManagerRotationEvent = {
        Step: "createSecret",
        SecretId: "test-secret",
        ClientRequestToken: "test-token",
      };

      const error = new Error("Test error");
      vi.mocked(createSecret).mockRejectedValue(error);

      await expect(handler(event)).rejects.toThrow("Test error");
    });
  });

  describe("cleanup events", () => {
    it("should handle cleanup event", async () => {
      const event: CleanupEvent = {
        action: "cleanup",
        secretArn: "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret",
      };

      await handler(event);

      expect(cleanupExpiredKeys).toHaveBeenCalledWith(
        expect.any(SecretsManagerClient),
        expect.any(S3Client),
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret"
      );
    });

    it("should handle errors in cleanup", async () => {
      const event: CleanupEvent = {
        action: "cleanup",
        secretArn: "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret",
      };

      const error = new Error("Cleanup error");
      vi.mocked(cleanupExpiredKeys).mockRejectedValue(error);

      await expect(handler(event)).rejects.toThrow("Cleanup error");
    });
  });
});
