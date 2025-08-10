import type { JWK } from "jose";

export interface SecretValue {
  /** The private key in PEM format used for signing JWTs */
  privateKeyPem: string;
  /** The public key in JWK format for inclusion in JWKS */
  publicKeyJwk: JWK;
  /** Unique key identifier used in JWT headers and JWKS */
  kid: string;
  /** Algorithm used for signing (e.g., RS256, ES256) */
  alg: string;
  /** ISO timestamp when the key was created */
  createdAt: string;
  /** ISO timestamp when the key was activated for signing (missing for future keys) */
  activatedAt?: string;
}
