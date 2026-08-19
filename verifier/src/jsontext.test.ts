// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from "vitest";
import { jsonTextProblem } from "./jsontext";

describe("duplicate members", () => {
  for (const [name, text] of [
    ["at the top level", `{"schema":"a","schema":"b"}`],
    ["nested in an object", `{"post":{"title":"a","title":"b"}}`],
    ["inside an array element", `{"claims":[{"excerpt":"a","excerpt":"b"}]}`],
    ["deep", `{"a":{"b":{"c":1,"c":2}}}`],
  ] as const) {
    it(`refuses: ${name}`, () => expect(jsonTextProblem(text)).not.toBeNull());
  }

  for (const [name, text] of [
    ["siblings in an array", `{"claims":[{"excerpt":"a"},{"excerpt":"b"}]}`],
    ["different objects", `{"post":{"title":"a"},"credential":{"title":"b"}}`],
    ["nested same name", `{"a":{"a":{"a":1}}}`],
    ["repeated array values", `{"ys":["a","a","a"]}`],
    ["a name inside a string value", `{"title":"\\"schema\\": twice"}`],
  ] as const) {
    it(`accepts: ${name}`, () => expect(jsonTextProblem(text)).toBeNull());
  }
});

describe("lone surrogates", () => {
  for (const [name, text] of [
    ["lone high", `{"title":"\\uD800"}`],
    ["lone low", `{"title":"\\uDC00"}`],
    ["high then text", `{"title":"\\uD800abc"}`],
    ["high then high", `{"title":"\\uD800\\uD800"}`],
  ] as const) {
    it(`refuses: ${name}`, () => expect(jsonTextProblem(text)).not.toBeNull());
  }

  for (const [name, text] of [
    ["a valid pair", `{"title":"\\uD83E\\uDDF5"}`],
    ["two valid pairs", `{"t":"\\uD83E\\uDDF5\\uD83E\\uDDF5"}`],
    ["an ordinary escape", `{"t":"caf\\u00e9"}`],
    ["an escaped backslash", `{"t":"not an escape: \\\\u0041"}`],
  ] as const) {
    it(`accepts: ${name}`, () => expect(jsonTextProblem(text)).toBeNull());
  }

  it("refuses a lone surrogate after a valid pair", () => {
    expect(jsonTextProblem(`{"t":"\\uD83E\\uDDF5\\uD800"}`)).not.toBeNull();
  });
});

// Go compares member names after decoding their escapes, so a name spelled
// two ways is one member there. A raw comparison here would let the
// duplicate through and split the two implementations.
describe("escaped member names", () => {
  it("sees an escaped spelling as the same member", () => {
    expect(jsonTextProblem(`{"schema":"a","\\u0073chema":"b"}`)).not.toBeNull();
  });

  it("still accepts genuinely different names that share a prefix", () => {
    expect(jsonTextProblem(`{"schema":"a","schema_version":"b"}`)).toBeNull();
  });
});

// Every number here is an integer, and 1, 1.0 and 1e0 are the same value
// with different spellings. JSON.parse cannot tell them apart, Go's
// decoder refuses two of the three, so the text is where it gets caught.
describe("number spelling", () => {
  for (const [name, text] of [
    ["a fractional count", `{"words":1.0}`],
    ["an exponent", `{"words":1e0}`],
    ["a real fraction", `{"chars":1.5}`],
    ["a negative exponent", `{"size":2E3}`],
  ] as const) {
    it(`refuses: ${name}`, () => expect(jsonTextProblem(text)).not.toBeNull());
  }

  for (const [name, text] of [
    ["plain integers", `{"words":48,"chars":261,"from":0,"to":18}`],
    ["a negative integer", `{"offset":-3}`],
    ["digits inside a string", `{"hash":"1.0e5 is text here"}`],
    ["a version string", `{"claim_generator":"folio-web/0.1.102"}`],
  ] as const) {
    it(`accepts: ${name}`, () => expect(jsonTextProblem(text)).toBeNull());
  }
});
