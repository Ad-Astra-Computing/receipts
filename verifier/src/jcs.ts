// SPDX-License-Identifier: Apache-2.0
// A small, dependency-free canonical JSON serializer.
//
// This implements the subset of RFC 8785 (JSON Canonicalization Scheme,
// JCS) that the Folio C2PA credential uses: objects with string keys
// sorted by UTF-16 code-unit order, arrays in their given order,
// strings with standard JSON escaping (no Unicode normalization),
// integers in JSON number form (the credential's numbers are safe
// integers), booleans and null. Non-finite numbers and undefined are
// rejected. We keep this auditable and free of npm dependencies rather
// than pull a general JCS library, because the signed payload's shape is
// known and small.

// Escape a string exactly as JSON.stringify does for the mandatory and
// short forms. JSON.stringify already emits the RFC 8785 string form:
// it escapes the two-character sequences (\", \\, \b, \f, \n, \r, \t),
// escapes control characters below U+0020 as \u00XX, and leaves every
// other code unit (including non-ASCII) literal, with no Unicode
// normalization. We defer to it for correctness and speed.
function encodeString(s: string): string {
  return JSON.stringify(s);
}

function encodeNumber(n: number): string {
  if (!Number.isFinite(n)) {
    throw new Error("jcs: non-finite number");
  }
  // The credential uses only safe integers (sizes, counts, offsets).
  // JSON.stringify renders these in canonical decimal form with no
  // leading zeros and no plus sign, matching JCS for integer values.
  return JSON.stringify(n);
}

// canonicalize returns the RFC 8785 JCS form of the supported subset.
export function canonicalize(value: unknown): string {
  if (value === null) return "null";

  const t = typeof value;

  if (t === "string") return encodeString(value as string);
  if (t === "number") return encodeNumber(value as number);
  if (t === "boolean") return (value as boolean) ? "true" : "false";

  if (t === "undefined") {
    throw new Error("jcs: undefined is not serializable");
  }
  if (t === "function" || t === "symbol" || t === "bigint") {
    throw new Error(`jcs: unsupported type ${t}`);
  }

  if (Array.isArray(value)) {
    const items = value.map((v) => canonicalize(v));
    return "[" + items.join(",") + "]";
  }

  // Plain object: sort keys by UTF-16 code-unit order using `<`, which
  // is JavaScript's default string comparison and is exactly the order
  // RFC 8785 mandates for JSON member keys.
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const parts: string[] = [];
  for (const k of keys) {
    const v = obj[k];
    if (v === undefined) {
      throw new Error(`jcs: undefined value at key ${k}`);
    }
    parts.push(encodeString(k) + ":" + canonicalize(v));
  }
  return "{" + parts.join(",") + "}";
}
