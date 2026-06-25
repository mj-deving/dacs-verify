import {
  buildAttestationBundle0004,
  buildAttestationBundleHtlc9,
} from "../examples/attestation-bundle-0004.ts";
import { bundleHash, verifyBundle, type AttestationBundle } from "../src/dacs5/index.ts";

export type ConvergenceBundle = Record<string, unknown>;

export interface ConvergenceResult {
  decision: string;
  hash: string;
  error?: string;
}

export interface ConvergenceAdapter {
  name: string;
  verify(bundle: ConvergenceBundle): ConvergenceResult;
}

const builtInPublicKeys = new Map<string, Uint8Array>([
  ...Object.entries(buildAttestationBundle0004().publicKeys),
  ...Object.entries(buildAttestationBundleHtlc9().publicKeys),
].map(([claim, key]) => [claim, new Uint8Array(Buffer.from(key, "base64url"))]));

function resolveKey(claim: string): Uint8Array | undefined {
  const portable = /(?:^|:)(?:0x)?([0-9a-fA-F]{64})$/.exec(claim);
  if (portable !== null) return new Uint8Array(Buffer.from(portable[1]!, "hex"));
  return builtInPublicKeys.get(claim);
}

export const dacsVerifyConvergenceAdapter: ConvergenceAdapter = {
  name: "dacs-verify",

  verify(bundle: ConvergenceBundle): ConvergenceResult {
    const out: ConvergenceResult = { decision: "error", hash: "" };
    try {
      const attestationBundle = bundle as unknown as AttestationBundle;
      out.hash = bundleHash(attestationBundle);
      out.decision = verifyBundle(attestationBundle, resolveKey);
    } catch (error) {
      out.error = error instanceof Error ? error.message : String(error);
    }
    return out;
  },
};

export default dacsVerifyConvergenceAdapter;
