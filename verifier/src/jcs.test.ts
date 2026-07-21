// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from "vitest";
import { canonicalize } from "./jcs";

describe("canonicalize (RFC 8785 subset)", () => {
  it("serializes primitives", () => {
    expect(canonicalize(null)).toBe("null");
    expect(canonicalize(true)).toBe("true");
    expect(canonicalize(false)).toBe("false");
    expect(canonicalize(0)).toBe("0");
    expect(canonicalize(42)).toBe("42");
    expect(canonicalize(-7)).toBe("-7");
    expect(canonicalize("hi")).toBe('"hi"');
    expect(canonicalize("")).toBe('""');
  });

  it("sorts object keys by UTF-16 code-unit order", () => {
    expect(canonicalize({ b: 1, a: 2, c: 3 })).toBe('{"a":2,"b":1,"c":3}');
    // Capitals sort before lowercase (A=0x41 < a=0x61).
    expect(canonicalize({ a: 1, A: 2 })).toBe('{"A":2,"a":1}');
    // Digit keys sort before letters (0x30 < 0x41).
    expect(canonicalize({ z: 1, "1": 2 })).toBe('{"1":2,"z":1}');
  });

  it("preserves array order and never sorts it", () => {
    expect(canonicalize([3, 1, 2])).toBe("[3,1,2]");
    expect(canonicalize(["b", "a"])).toBe('["b","a"]');
    expect(canonicalize([])).toBe("[]");
  });

  it("nests objects and arrays with sorted keys at every level", () => {
    const v = { outer: { z: [1, { y: 1, x: 2 }], a: "v" }, first: true };
    expect(canonicalize(v)).toBe(
      '{"first":true,"outer":{"a":"v","z":[1,{"x":2,"y":1}]}}',
    );
  });

  it("escapes strings with standard JSON escaping, no normalization", () => {
    expect(canonicalize('a"b')).toBe('"a\\"b"');
    expect(canonicalize("a\\b")).toBe('"a\\\\b"');
    expect(canonicalize("line\nfeed")).toBe('"line\\nfeed"');
    expect(canonicalize("tab\tend")).toBe('"tab\\tend"');
    // Control character below U+0020 escapes as \u00XX.
    expect(canonicalize("")).toBe('"\\u0001"');
    // Non-ASCII stays literal (no escaping, no NFC/NFD normalization).
    const s = "é"; // e + combining acute, NOT precomposed
    expect(canonicalize(s)).toBe('"' + s + '"');
    expect(canonicalize("é")).toBe('"é"'); // precomposed stays distinct
  });

  it("rejects non-finite numbers", () => {
    expect(() => canonicalize(Infinity)).toThrow();
    expect(() => canonicalize(-Infinity)).toThrow();
    expect(() => canonicalize(NaN)).toThrow();
  });

  it("rejects undefined values", () => {
    expect(() => canonicalize(undefined)).toThrow();
    expect(() => canonicalize({ a: undefined })).toThrow();
  });

  it("matches a known small credential-shaped fixture", () => {
    const cred = {
      "@context": "https://c2pa.org/ns/manifest/1.4",
      type: "ContentCredential",
      asset: { sha256: "ab", size: 3, mime: "text/markdown" },
      signature: { alg: "Ed25519", public_key: "k" },
    };
    expect(canonicalize(cred)).toBe(
      '{"@context":"https://c2pa.org/ns/manifest/1.4",' +
        '"asset":{"mime":"text/markdown","sha256":"ab","size":3},' +
        '"signature":{"alg":"Ed25519","public_key":"k"},' +
        '"type":"ContentCredential"}',
    );
  });
});
