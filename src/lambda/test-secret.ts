import type { S3Client } from "@aws-sdk/client-s3";
import type { SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import { createLocalJWKSet, importPKCS8, jwtVerify, SignJWT } from "jose";
import { getEnvironmentConfig, getJwksFromS3, getSecretValue } from "./utils";

export async function testSecret(
  secretsClient: SecretsManagerClient,
  s3Client: S3Client,
  secretId: string,
  token: string,
): Promise<void> {
  console.log("Starting testSecret step");

  const pendingSecret = await getSecretValue(secretsClient, {
    SecretId: secretId,
    VersionId: token,
    VersionStage: "AWSPENDING",
  });
  if (!pendingSecret) {
    throw new Error("AWSPENDING version not found");
  }

  const { privateKey, alg, kid } = pendingSecret.secretValue;

  const testPayload = {
    sub: "test-subject",
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 300,
    test: true,
  };

  console.log(`Signing test JWT with private key ${kid}`);
  const privateKeyObject = await importPKCS8(privateKey, alg);

  const jwt = await new SignJWT(testPayload)
    .setProtectedHeader({
      alg,
      kid,
    })
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKeyObject);

  console.log("Loading JWKS from S3 for verification");
  const { bucketName, bucketPath } = getEnvironmentConfig();
  const jwksDocument = await getJwksFromS3(s3Client, bucketName, bucketPath);

  if (!jwksDocument.keys || jwksDocument.keys.length === 0) {
    throw new Error("No keys found in JWKS document");
  }

  const jwks = createLocalJWKSet(jwksDocument);

  console.log("Verifying test JWT with JWKS");
  try {
    const { payload } = await jwtVerify(jwt, jwks);

    if (payload.test !== true) {
      throw new Error("Test payload verification failed");
    }

    console.log("JWT verification successful");
  } catch (error) {
    console.error("JWT verification failed:", error);
    throw new Error(`JWT verification failed: ${error}`);
  }

  console.log("testSecret completed successfully");
}
