// SPDX-License-Identifier: Apache-2.0
//
// Two properties of a receipts file cannot be checked after parsing,
// because parsing destroys the evidence. Both are checked here, on the
// text as received, and the Go module checks the same two in
// receipts/jsontext.go.
//
// Duplicate member names: every parser keeps one value and discards the
// other, and they do not all keep the same one. JSON.parse silently
// takes the last. A document with a duplicate therefore means different
// things to different verifiers while the signature covers only one of
// those meanings, so it is refused rather than resolved.
//
// Lone surrogates: a \uD800-\uDFFF escape with no partner is not a
// character. JavaScript preserves it and Go replaces it with U+FFFD, so
// the two canonicalize different strings and reach different digests for
// the same file. RFC 8785 requires rejection.

/** Returns the first problem with the raw text, or null. */
export function jsonTextProblem(text: string): string | null {
  return loneSurrogateProblem(text) ?? duplicateMemberProblem(text);
}

function loneSurrogateProblem(text: string): string | null {
  for (let i = 0; i + 5 < text.length; i++) {
    if (text[i] !== "\\" || text[i + 1] !== "u") continue;
    let backslashes = 0;
    for (let j = i - 1; j >= 0 && text[j] === "\\"; j--) backslashes++;
    if (backslashes % 2 === 1) continue; // the backslash is itself escaped

    const code = hex4(text.slice(i + 2, i + 6));
    if (code === null) continue; // malformed escapes are the parser's business
    const isHigh = code >= 0xd800 && code <= 0xdbff;
    const isLow = code >= 0xdc00 && code <= 0xdfff;
    if (!isHigh && !isLow) continue;

    if (isHigh && text[i + 6] === "\\" && text[i + 7] === "u") {
      const next = hex4(text.slice(i + 8, i + 12));
      if (next !== null && next >= 0xdc00 && next <= 0xdfff) {
        i += 11; // a well-formed pair
        continue;
      }
    }
    return `the file contains a lone surrogate escape (\\u${code.toString(16).toUpperCase().padStart(4, "0")}), which is not a character`;
  }
  return null;
}

function hex4(s: string): number | null {
  if (s.length !== 4 || !/^[0-9a-fA-F]{4}$/.test(s)) return null;
  return parseInt(s, 16);
}

/**
 * Walks the text and reports any object that names the same member
 * twice. This is a scanner rather than a parse: JSON.parse has already
 * thrown the duplicate away by the time a reviver sees the object.
 */
function duplicateMemberProblem(text: string): string | null {
  // Per open object: the names seen so far. null marks an open array.
  const stack: (Set<string> | null)[] = [];
  const path: string[] = [];
  let expectKey = false;
  let i = 0;

  const readString = (): string | null => {
    // text[i] is the opening quote.
    let out = "";
    i++;
    while (i < text.length) {
      const c = text[i];
      if (c === "\\") {
        out += text[i] + text[i + 1];
        i += 2;
        continue;
      }
      if (c === '"') {
        i++;
        return out;
      }
      out += c;
      i++;
    }
    return null; // unterminated: the parser will report it
  };

  while (i < text.length) {
    const c = text[i];
    if (c === '"') {
      const name = readString();
      if (name === null) return null;
      const top = stack[stack.length - 1];
      if (expectKey && top) {
        if (top.has(name)) {
          const where = path.length > 0 ? path.join(".") : "the top level";
          return `"${name}" appears twice in ${where}; a duplicate member means different things to different parsers`;
        }
        top.add(name);
        path.push(name);
        expectKey = false;
      }
      continue;
    }
    if (c === "{") {
      stack.push(new Set());
      expectKey = true;
    } else if (c === "[") {
      stack.push(null);
      expectKey = false;
    } else if (c === "}" || c === "]") {
      stack.pop();
      path.pop();
      expectKey = stack.length > 0 && stack[stack.length - 1] !== null;
    } else if (c === ",") {
      const top = stack[stack.length - 1];
      if (top) {
        expectKey = true;
        path.pop();
      }
    }
    i++;
  }
  return null;
}
