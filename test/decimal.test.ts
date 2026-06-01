import { test, expect } from "bun:test";
import {
  canonicalDecimal,
  isCanonicalDecimal,
  assertPositiveAmount,
  CanonicalDecimalError,
} from "../src/decimal.ts";
import { contentHash } from "../src/hash.ts";

test("CD-1 worked cases from §14.4: 1.50 / 01.5 / 1.500 all → 1.5", () => {
  expect(canonicalDecimal("1.50")).toBe("1.5");
  expect(canonicalDecimal("01.5")).toBe("1.5");
  expect(canonicalDecimal("1.500")).toBe("1.5");
});

test("CD-1 normal forms", () => {
  expect(canonicalDecimal("1")).toBe("1");
  expect(canonicalDecimal("100")).toBe("100");
  expect(canonicalDecimal("0.0")).toBe("0");
  expect(canonicalDecimal("000")).toBe("0");
  expect(canonicalDecimal(".5")).toBe("0.5");
  expect(canonicalDecimal("0.50")).toBe("0.5");
});

test("CD-1 rejects exponent / sign-plus / non-numeric", () => {
  expect(() => canonicalDecimal("1e3")).toThrow(CanonicalDecimalError);
  expect(() => canonicalDecimal("+1")).toThrow(CanonicalDecimalError);
  expect(() => canonicalDecimal("abc")).toThrow(CanonicalDecimalError);
  expect(() => canonicalDecimal("")).toThrow(CanonicalDecimalError);
});

test("economically-equal amounts produce identical content hashes (the point of CD-1)", () => {
  const a = contentHash({ amount: canonicalDecimal("1.50"), currency: "USDC" });
  const b = contentHash({ amount: canonicalDecimal("1.500"), currency: "USDC" });
  expect(a).toBe(b);
  // ...and a verifier comparing raw (non-canonicalised) strings would WRONGLY differ:
  const rawA = contentHash({ amount: "1.50", currency: "USDC" });
  const rawB = contentHash({ amount: "1.500", currency: "USDC" });
  expect(rawA).not.toBe(rawB);
});

test("isCanonicalDecimal is the idempotence check", () => {
  expect(isCanonicalDecimal("1.5")).toBe(true);
  expect(isCanonicalDecimal("1.50")).toBe(false);
  expect(isCanonicalDecimal("1e3")).toBe(false);
});

test("§9.3 positivity: amount MUST be > 0", () => {
  expect(assertPositiveAmount("1.5")).toBe("1.5");
  expect(() => assertPositiveAmount("0")).toThrow(/> 0/);
  expect(() => assertPositiveAmount("0.0")).toThrow(/> 0/);
  expect(() => assertPositiveAmount("-1.5")).toThrow(/> 0/);
});
