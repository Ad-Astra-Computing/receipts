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
  return loneSurrogateProblem(text) ?? numberSpellingProblem(text) ?? duplicateMemberProblem(text);
}

/**
 * Every number in a receipt is an integer (SPEC section 4), and the
 * spelling is part of the wire form: 1, never 1.0 or 1e0. JSON.parse
 * turns all three into the same value, so the spelling has to be checked
 * on the text. Go's typed decoder refuses the other two, and without
 * this the browser would accept a file the library rejects.
 */
function numberSpellingProblem(text: string): string | null {
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      if (c === "\\") i++;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') {
      inString = true;
      continue;
    }
    if (c !== "-" && (c < "0" || c > "9")) continue;
    // A number token: read to its end and judge the whole of it.
    let j = i;
    if (text[j] === "-") j++;
    const start = j;
    while (j < text.length && /[0-9.eE+-]/.test(text[j])) j++;
    const token = text.slice(start, j);
    if (token.includes(".") || token.includes("e") || token.includes("E")) {
      return `${text.slice(i, j)} is written with a fractional part or an exponent; this format carries whole numbers only`;
    }
    i = j - 1;
  }
  return null;
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
    // text[i] is the opening quote. The raw span is collected and then
    // decoded, because two spellings of one name are one member: Go
    // compares decoded names, so "schema" and "\u0073chema" are a
    // duplicate there and would slip past a raw comparison here.
    const start = i;
    i++;
    while (i < text.length) {
      const c = text[i];
      if (c === "\\") {
        i += 2;
        continue;
      }
      if (c === '"') {
        i++;
        const raw = text.slice(start, i);
        try {
          return JSON.parse(raw) as string;
        } catch {
          return raw; // malformed: the parser will report it properly
        }
      }
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
