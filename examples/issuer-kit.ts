import {
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  sign as nodeSign,
  type KeyObject,
} from "node:crypto";
import { canonicalize, withoutSignature } from "../src/canonicalize.ts";
import { sha256Hex } from "../src/hash.ts";
import { buildSignedBytes } from "../src/signing.ts";

// DEMO ISSUER KIT — NOT part of the verifier.
//
// This is the ONLY file in the repo that holds a private key or produces a
// signature. It exists to generate signed fixtures and drive the end-to-end
// scenario. The verifier (`src/`) never imports it and never signs (ISC-38):
// the verifier verifies, the issuer issues. Keys are ephemeral, generated per
// run, and never persisted (only the raw public key is emitted, into vectors).

export interface Keypair {
  privateKey: KeyObject;
  /** Raw 32-byte Ed25519 public key. */
  publicKeyRaw: Uint8Array;
  /** base64url of the raw public key — the form a DACS claim would carry. */
  publicKeyB64u: string;
}

function fromPrivateKey(privateKey: KeyObject): Keypair {
  const jwk = createPublicKey(privateKey).export({ format: "jwk" }) as { x: string };
  const publicKeyRaw = new Uint8Array(Buffer.from(jwk.x, "base64url"));
  return { privateKey, publicKeyRaw, publicKeyB64u: jwk.x };
}

export function generateKeypair(): Keypair {
  const { privateKey } = generateKeyPairSync("ed25519");
  return fromPrivateKey(privateKey);
}

// Standard PKCS8 DER wrapper for an Ed25519 private key; the 32-byte seed is
// appended verbatim. Lets us derive a DETERMINISTIC keypair from a fixed seed so
// the emitted vectors are byte-stable across runs (Ed25519 signing is itself
// deterministic given key + message). Demo-only — real keys are never seeded.
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function keypairFromSeed(seedHex: string): Keypair {
  const seed = Buffer.from(seedHex, "hex");
  if (seed.length !== 32) throw new Error("Ed25519 seed must be 32 bytes (64 hex chars)");
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);
  return fromPrivateKey(createPrivateKey({ key: der, format: "der", type: "pkcs8" }));
}

/**
 * Sign an artifact exactly as §7.7 specifies:
 *   signed_bytes := domain_separator || sha256_hex(JCS(signed scope))
 * Returns the base64url of the raw 64-byte Ed25519 signature.
 */
export function signArtifact(
  separator: string,
  doc: Record<string, unknown>,
  privateKey: KeyObject,
  signatureFields: string[] = ["signature"],
): string {
  const scope = withoutSignature(doc, ...signatureFields);
  const hash = sha256Hex(canonicalize(scope));
  const bytes = buildSignedBytes(separator, hash);
  return nodeSign(null, bytes, privateKey).toString("base64url");
}
