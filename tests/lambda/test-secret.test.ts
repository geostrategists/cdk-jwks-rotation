import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { GetSecretValueCommand, SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import { mockClient } from "aws-sdk-client-mock";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { testSecret } from "../../src/lambda/test-secret";

const s3Mock = mockClient(S3Client);
const secretsManagerMock = mockClient(SecretsManagerClient);
const mockedS3Client: S3Client = s3Mock as unknown as S3Client;
const mockedSecretsManagerClient: SecretsManagerClient =
  secretsManagerMock as unknown as SecretsManagerClient;

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

describe("Test Secret", () => {
  const mockPrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCRrc4aU7yRL4JL
VxUqYq61YEAUefg0ASD9c5TnZ49EDute4+eHQG2RO0lr4lqkNXw2IuJ7RT4Y4CQ3
IWAl6eLItDCtufFyWe0xsUzum/PSees7P7iqOLo5bGM64+BB3QT9ttMnOLOmZ7VX
vRX1fcmalfSYPQGqj3CDzqxsKaDBQxlMeA6XLQVUxJeDNgBlVoyizXeydQCvB34k
qkKftMp1DXWSSji3UXlrv702bmxSjYExSSktmKlJQ5Lq5lVnvRj5seCEX9pXPes8
CsWgJ/X2Zwdtt1BVjCe6d+9N/xxT/s6AvffCc0URcLaaCXVdWgXS/9pMn6mI0tuj
ukdHUsIfAgMBAAECggEAG9x3zIUzTTke3DXdcGvLKhksaD4jgB6vJooScmdV+Rg5
X76Kq01hJyOFmUKDP2CTTu9BDX5ir/M+OeUCNH4Ux3nezXsAeHRGbviP1BqzeQ+k
M4KuWK/cvdrC56JpY29X4wYyQBASG8M95XfeWUMjaZNAYlVYmjwwsqS2SUF040Ee
F/yMIeoTsFGyPOQhtgllD4iEzc+LD2WSnqVtQl0gb0Qp++5lancEhuxMwCnB7Oyy
RI2dIYUJnmiQjTN2GJ8q+dJj4Orp9dfpu7aUphIoKt4ReX9d4M7+41xnT4FxONgv
xYxlUa5+5Nvyfm1DA+87s7dw7lFgpttqxcVhurNBQQKBgQDDW5zWIltGMR3MJOb6
mbj2XmgbAELfX4k9svvfBQouEZd+NhBddlZgbqcmgQnoqh/LPdrhLJYi72I+oEcP
1PWOYzi2LxgEOJFm2AWrCUAw/4m0EcvGKt3ruTpeeuUfMEjNAiDxx5hYoL2LK1sT
ltAjxJrP1TJSwUf/VBtJCcxwrwKBgQC+5mLLqpJ61PLDEGb9F1OrPpqfReX4UePs
nh+0sYiwpDwjuF+SxTMpsnK/th4WyB1WLPLNMGQhYkqTxoQ+gTq+UrfK9xEfLtpG
zFdypXjRpbvdB1h/F9TXwR9IcTZStknyq/452z3t9v5tMQEcweBzAnGHBQs9sYYB
066wdl3BkQKBgQCRNF72qsK9AXTsb+FfEzNvq+wlZaRO82vG+GpN8ikG5Px9SyIO
1g6NzrFe5TrAPPM01d0C0Wkmvld/xRIMqnV6SDW29HodaQ5qKtbLsiyMPuPTfAbC
XMpmk17XKvFypSj3eEWUcI7EEXXRI4Cmpso+S7vmDslAyXkCRzmgqC/U8QKBgAEO
r59nK3aItWuFLLzcIzeAmkSlk3eDpJqL6asLjLFFx5t/CvB6LSVe+qm7LYF8zETM
7O9cBEH3FGirIdJiztt9A82Y/rxIeycHPLjC1995Zof74W6ayDAFvtGc5usgXVp9
v2O8piQqSRB7xADPxhl8+vn/eid2U0KxVHdfwHcxAoGBAJmpoyWo8238JVKnI/uP
pnwV2Q+6Smxdt5Q+ZEGkjL3bNn/ca9XVRjldSIy6yyyJFE0oMGa4TC4qHKCV1/FT
uxLd7ybT+osVuaJ5QA8Vv1SsGBK5GzfolZ3HPzgfxYFEW6bwAdOynwxA8raoaqgN
zTxPPg/R3Ih9XuBRmrGGqhAH
-----END PRIVATE KEY-----`;

  beforeEach(() => {
    s3Mock.reset();
    secretsManagerMock.reset();
    vi.clearAllMocks();
  });

  it("should successfully verify a valid key", async () => {
    const mockPublicJwk = {
      kty: "RSA",
      kid: "test-kid",
      alg: "RS256",
      use: "sig",
      n: "ka3OGlO8kS-CS1cVKmKutWBAFHn4NAEg_XOU52ePRA7rXuPnh0BtkTtJa-JapDV8NiLie0U-GOAkNyFgJeniyLQwrbnxclntMbFM7pvz0nnrOz-4qji6OWxjOuPgQd0E_bbTJzizpme1V70V9X3JmpX0mD0Bqo9wg86sbCmgwUMZTHgOly0FVMSXgzYAZVaMos13snUArwd-JKpCn7TKdQ11kko4t1F5a7-9Nm5sUo2BMUkpLZipSUOS6uZVZ70Y-bHghF_aVz3rPArFoCf19mcHbbdQVYwnunfvTf8cU_7OgL33wnNFEXC2mgl1XVoF0v_aTJ-piNLbo7pHR1LCHw",
      e: "AQAB",
    };

    secretsManagerMock
      .on(GetSecretValueCommand, {
        SecretId: "test-secret",
        VersionStage: "AWSPENDING",
      })
      .resolves({
        SecretString: JSON.stringify({
          privateKeyPem: mockPrivateKey,
          kid: "test-kid",
          alg: "RS256",
          createdAt: new Date().toISOString(),
        }),
        VersionId: "test-version-id",
        VersionStages: ["AWSPENDING"],
      });

    s3Mock.on(GetObjectCommand).resolves({
      Body: {
        transformToString: () =>
          Promise.resolve(
            JSON.stringify({
              keys: [mockPublicJwk],
            }),
          ),
      } as any,
    });

    await expect(
      testSecret(mockedSecretsManagerClient, mockedS3Client, "test-secret", "test-token"),
    ).resolves.not.toThrow();

    expect(secretsManagerMock.commandCalls(GetSecretValueCommand)).toHaveLength(1);
    expect(s3Mock.commandCalls(GetObjectCommand)).toHaveLength(1);
  });

  it("should throw error when AWSPENDING secret not found", async () => {
    secretsManagerMock.on(GetSecretValueCommand).rejects({ name: "ResourceNotFoundException" });

    await expect(
      testSecret(mockedSecretsManagerClient, mockedS3Client, "test-secret", "test-token"),
    ).rejects.toThrow("AWSPENDING version not found");
  });

  it("should throw error when JWKS file not found", async () => {
    secretsManagerMock.on(GetSecretValueCommand).resolves({
      SecretString: JSON.stringify({
        privateKeyPem: mockPrivateKey,
        kid: "test-kid",
        alg: "RS256",
        createdAt: new Date().toISOString(),
      }),
      VersionId: "test-version-id",
      VersionStages: ["AWSPENDING"],
    });

    s3Mock.on(GetObjectCommand).rejects({ name: "NoSuchKey" });

    await expect(
      testSecret(mockedSecretsManagerClient, mockedS3Client, "test-secret", "test-token"),
    ).rejects.toThrow("No keys found in JWKS document");
  });

  it("should throw error when key not found in JWKS", async () => {
    secretsManagerMock.on(GetSecretValueCommand).resolves({
      SecretString: JSON.stringify({
        privateKeyPem: mockPrivateKey,
        kid: "test-kid",
        alg: "RS256",
        createdAt: new Date().toISOString(),
      }),
      VersionId: "test-version-id",
      VersionStages: ["AWSPENDING"],
    });

    s3Mock.on(GetObjectCommand).resolves({
      Body: {
        transformToString: () =>
          Promise.resolve(
            JSON.stringify({
              keys: [
                {
                  kty: "RSA",
                  kid: "different-kid",
                  alg: "RS256",
                  use: "sig",
                  n: "different-key",
                  e: "AQAB",
                },
              ],
            }),
          ),
      } as any,
    });

    await expect(
      testSecret(mockedSecretsManagerClient, mockedS3Client, "test-secret", "test-token"),
    ).rejects.toThrow("no applicable key found in the JSON Web Key Set");
  });

  it("should handle S3 errors", async () => {
    secretsManagerMock.on(GetSecretValueCommand).resolves({
      SecretString: JSON.stringify({
        privateKeyPem: mockPrivateKey,
        kid: "test-kid",
        alg: "RS256",
        createdAt: new Date().toISOString(),
      }),
      VersionId: "test-version-id",
      VersionStages: ["AWSPENDING"],
    });

    s3Mock.on(GetObjectCommand).rejects(new Error("S3 Error"));

    await expect(
      testSecret(mockedSecretsManagerClient, mockedS3Client, "test-secret", "test-token"),
    ).rejects.toThrow("S3 Error");
  });

  it("should handle secrets manager errors", async () => {
    secretsManagerMock.on(GetSecretValueCommand).rejects(new Error("SecretsManager Error"));

    await expect(
      testSecret(mockedSecretsManagerClient, mockedS3Client, "test-secret", "test-token"),
    ).rejects.toThrow("SecretsManager Error");
  });
});
