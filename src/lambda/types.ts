import type { JWK } from "jose";

export interface SecretValue {
  privateKey: string;
  publicJwk: JWK;
  kid: string;
  alg: string;
  createdAt: string;
  activatedAt?: string;
}
