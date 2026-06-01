import { test, expect } from "bun:test";
import { canonicalize, withoutSignature } from "../src/canonicalize.ts";

test("objects: members ordered by UTF-16 code unit of key", () => {
  expect(canonicalize({ b: 1, a: 2, A: 3 })).toBe('{"A":3,"a":2,"b":1}');
});

test("nested objects + array order preserved", () => {
  expect(canonicalize({ z: [3, 1, 2], a: { y: 1, x: 2 } })).toBe(
    '{"a":{"x":2,"y":1},"z":[3,1,2]}',
  );
});

test("string escaping per JCS (only required escapes)", () => {
  expect(canonicalize('a"b\\c\n\t')).toBe('"a\\"b\\\\c\\n\\t"');
  // forward slash and non-ASCII are NOT escaped
  expect(canonicalize("a/bé")).toBe('"a/bé"');
  // control char below 0x20 → \u00XX
  expect(canonicalize(String.fromCharCode(1))).toBe('"\\u0001"');
});

test("safe integers serialise as plain decimals", () => {
  expect(canonicalize(0)).toBe("0");
  expect(canonicalize(-0)).toBe("0");
  expect(canonicalize(42)).toBe("42");
  expect(canonicalize(Number.MAX_SAFE_INTEGER)).toBe("9007199254740991");
});

test("enforces DACS §7.1: non-integer / unsafe-integer numbers throw", () => {
  expect(() => canonicalize(1.5)).toThrow(/§7.1/);
  expect(() => canonicalize(Number.MAX_SAFE_INTEGER + 2)).toThrow(/§7.1/);
  expect(() => canonicalize(Infinity)).toThrow();
});

test("withoutSignature strips the signed-scope field(s)", () => {
  expect(withoutSignature({ a: 1, signature: "x" })).toEqual({ a: 1 });
  expect(withoutSignature({ a: 1, signatures: [] })).toEqual({ a: 1 });
  expect(withoutSignature({ a: 1, sig: "x" }, "sig")).toEqual({ a: 1 });
});

test("undefined-valued members are omitted (JSON semantics)", () => {
  expect(canonicalize({ a: 1, b: undefined })).toBe('{"a":1}');
});
