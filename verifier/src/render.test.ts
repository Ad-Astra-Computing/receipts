// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from "vitest";
import { byteRangesToStringRanges, disclosedChars, excerptProse, mergeRanges, stripFrontmatter } from "./render";

// Reconstruct the body the way tapeBody does: plain text between the
// merged intervals, "marked" text inside them. The result must equal
// the original body exactly, or the on-screen text would diverge from
// the hashed body.
function reconstruct(body: string, ranges: { from: number; to: number }[]): string {
  const merged = mergeRanges(ranges, body.length);
  let out = "";
  let cursor = 0;
  for (const r of merged) {
    if (r.from > cursor) out += body.slice(cursor, r.from);
    out += body.slice(r.from, r.to);
    cursor = r.to;
  }
  if (cursor < body.length) out += body.slice(cursor);
  return out;
}

describe("stripFrontmatter", () => {
  it("removes a TOML +++ block and reports the offset", () => {
    const body = '+++\ntitle = "X"\n+++\n\nHello world.\n';
    const { prose, offset } = stripFrontmatter(body);
    expect(prose).toBe("Hello world.\n");
    expect(body.slice(offset)).toBe(prose);
  });
  it("removes a YAML --- block", () => {
    const { prose } = stripFrontmatter("---\ntitle: X\n---\nBody.");
    expect(prose).toBe("Body.");
  });
  it("leaves frontmatter-less bodies untouched", () => {
    const { prose, offset } = stripFrontmatter("Just prose.");
    expect(prose).toBe("Just prose.");
    expect(offset).toBe(0);
  });
});

describe("excerptProse", () => {
  it("shows the whole prose when the end is within reach", () => {
    const prose =
      "When anyone can generate text, a clean draft proves nothing. What still counts is the work behind it: the sources checked, the lines cut, and the parts written with an AI assistant, disclosed and signed. This note is one of them, so you can see how it was made.";
    const { text, ellipsis } = excerptProse(prose, 167);
    expect(ellipsis).toBe(false);
    expect(text).toBe(prose);
    expect(text.endsWith("how it was made.")).toBe(true);
  });
  it("never ends mid-word when it truncates", () => {
    const prose = "alpha bravo charlie delta echo foxtrot golf hotel india juliet " + "x".repeat(400);
    const { text, ellipsis } = excerptProse(prose, 5);
    expect(ellipsis).toBe(true);
    // The kept text (minus the appended ellipsis is handled in tapeBody)
    // must not end in the middle of a word: last char is a word char only
    // if the following char in the source was whitespace or the string end.
    const next = prose[text.length];
    expect(next === undefined || /\s/.test(next) || /\s/.test(text[text.length - 1])).toBe(true);
  });
  it("keeps at least the last marked range", () => {
    const prose = "one two three four five six seven eight nine ten " + "y".repeat(300);
    const minEnd = 40;
    const { text } = excerptProse(prose, minEnd);
    expect(text.length).toBeGreaterThanOrEqual(minEnd);
  });
});

describe("mergeRanges + tapeBody reconstruction", () => {
  const body = "The quick brown fox jumps over the lazy dog.";
  it("reconstructs the body with disjoint ranges", () => {
    expect(reconstruct(body, [{ from: 4, to: 9 }, { from: 20, to: 25 }])).toBe(body);
  });
  it("reconstructs the body with overlapping ranges (no duplication)", () => {
    expect(reconstruct(body, [{ from: 4, to: 15 }, { from: 10, to: 25 }])).toBe(body);
  });
  it("reconstructs the body with nested + out-of-bounds ranges", () => {
    expect(reconstruct(body, [{ from: -5, to: 999 }, { from: 4, to: 9 }])).toBe(body);
  });
  it("produces sorted, non-overlapping intervals", () => {
    const m = mergeRanges([{ from: 20, to: 25 }, { from: 4, to: 22 }, { from: 0, to: 3 }], body.length);
    for (let i = 1; i < m.length; i++) expect(m[i].from).toBeGreaterThan(m[i - 1].to);
  });
});

describe("disclosedChars (AI-disclosed percentage)", () => {
  it("sums non-overlapping ranges", () => {
    expect(disclosedChars([{ from: 0, to: 10 }, { from: 20, to: 25 }], 100)).toBe(15);
  });

  it("merges overlapping ranges so it can't exceed the body", () => {
    // Two heavily overlapping ranges must not double-count.
    expect(disclosedChars([{ from: 0, to: 80 }, { from: 40, to: 100 }], 100)).toBe(100);
  });

  it("clamps out-of-bounds ranges to the body length", () => {
    expect(disclosedChars([{ from: -50, to: 5000 }], 100)).toBe(100);
  });

  it("drops inverted or empty ranges", () => {
    expect(disclosedChars([{ from: 30, to: 10 }, { from: 5, to: 5 }], 100)).toBe(0);
  });

  it("never returns more than the body length", () => {
    const many = Array.from({ length: 50 }, () => ({ from: 0, to: 100 }));
    expect(disclosedChars(many, 100)).toBeLessThanOrEqual(100);
  });
});

// ai_ranges are UTF-8 byte offsets into the published body (SPEC section
// 4). JavaScript strings are indexed in UTF-16 code units, so any
// non-ASCII character before a range shifts every later index: an accent
// costs one extra byte, an emoji three. Slicing with the raw numbers
// highlights the wrong words, and does it silently, only for text that
// is not plain English.
describe("byteRangesToStringRanges", () => {
  const bytes = (s: string) => new TextEncoder().encode(s).length;

  it("maps byte offsets onto string indices when the text is not ASCII", () => {
    const prefix = "Café ☕ costs €3 — ";
    const marked = "the model wrote this";
    const body = prefix + marked + " and then a human continued.";
    const from = bytes(prefix);
    const to = from + bytes(marked);

    const [r] = byteRangesToStringRanges(body, [{ from, to }]);
    expect(body.slice(r.from, r.to)).toBe(marked);
    // The naive reading is wrong, which is the whole point.
    expect(body.slice(from, to)).not.toBe(marked);
  });

  it("handles characters outside the basic plane", () => {
    const prefix = "A 🧵 thread: ";
    const marked = "generated sentence";
    const body = prefix + marked + ".";
    const from = bytes(prefix);
    const [r] = byteRangesToStringRanges(body, [{ from, to: from + bytes(marked) }]);
    expect(body.slice(r.from, r.to)).toBe(marked);
  });

  it("is the identity for pure ASCII", () => {
    const body = "plain ascii body text";
    const [r] = byteRangesToStringRanges(body, [{ from: 6, to: 11 }]);
    expect(r).toEqual({ from: 6, to: 11 });
    expect(body.slice(r.from, r.to)).toBe("ascii");
  });

  it("clamps an offset that lands inside a character rather than splitting it", () => {
    const body = "é abc";
    // 1 is inside the two-byte é.
    const [r] = byteRangesToStringRanges(body, [{ from: 1, to: 3 }]);
    expect(r.from).toBeGreaterThanOrEqual(0);
    expect(r.to).toBeLessThanOrEqual(body.length);
    expect(() => body.slice(r.from, r.to)).not.toThrow();
  });
});
