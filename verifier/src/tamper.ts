// SPDX-License-Identifier: Apache-2.0
//
// The page's central claim is that changing a receipt after signing is
// detectable. Asserting that is weak; a reader has no reason to take our
// word for it. These are the changes a forger would actually make, and
// the buttons apply them to the demo receipt so the real verifier can
// refuse it in front of you.
//
// Every mutation here is honest: nothing is rigged to fail. The bundle
// is re-verified by the same code path a dropped file takes, and it
// fails because the signature no longer covers what the bundle says.

import type { Bundle } from "./verify";

export type Tamper = "body" | "timeline" | "range" | "signature";

export interface Tampered {
  bundle: Bundle;
  body: string | undefined;
  /** What was done, in the reader's terms. */
  note: string;
  /**
   * The change itself, so the reader can see what moved rather than
   * being told something moved. A demonstration that hides its own edit
   * asks for the same trust it is trying to replace.
   */
  before: string;
  after: string;
}

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

/** Applies one forgery to a receipt and its published text. */
export function tamper(kind: Tamper, bundle: Bundle, body: string | undefined): Tampered {
  const b = clone(bundle);
  switch (kind) {
    case "body": {
      // The commonest forgery: publish something other than what was
      // signed. One word is enough.
      const text = body ?? "";
      const word = text.includes("receipts") ? "receipts" : text.trim().split(/\s+/)[0] ?? "";
      const edited = word ? text.replace(word, "invoices") : `${text} edited`;
      return {
        bundle: b,
        body: edited,
        note: "One word of the published text was changed.",
        before: word,
        after: "invoices",
      };
    }
    case "timeline": {
      // Make the work look different: swap two checkpoints so the draft
      // appears to have grown in another order.
      const cps = b.timeline?.checkpoints ?? [];
      let before = "";
      let after = "";
      if (cps.length >= 2) {
        const [first, second] = [cps[0], cps[1]];
        before = `${first.words} words at ${clock(first.at)}, then ${second.words} at ${clock(second.at)}`;
        after = `${second.words} words at ${clock(second.at)}, then ${first.words} at ${clock(first.at)}`;
        cps[0] = second;
        cps[1] = first;
      }
      return {
        bundle: b,
        body,
        note: "The first two checkpoints were swapped, as if the drafts arrived in another order.",
        before,
        after,
      };
    }
    case "range": {
      // Shrink a disclosure: claim less of the text was AI-written.
      const ranges = b.ai_ranges ?? [];
      let before = "";
      let after = "";
      if (ranges.length > 0) {
        const r = ranges[0];
        const shorter = { ...r, to: Math.max(r.from + 1, r.to - 6) };
        before = excerpt(body, r.from, r.to);
        after = excerpt(body, shorter.from, shorter.to);
        ranges[0] = shorter;
      }
      return {
        bundle: b,
        body,
        note: "A disclosed AI passage was made shorter, hiding part of what was declared.",
        before,
        after,
      };
    }
    case "signature": {
      // Sign it with someone else's key, or forge the value.
      const value = b.signature?.value ?? "";
      const forged = flipLast(value);
      b.signature = { ...b.signature, value: forged };
      return {
        bundle: b,
        body,
        note: "The last character of the signature was changed.",
        before: tail(value),
        after: tail(forged),
      };
    }
  }
}

/** The time part of a canonical timestamp, for a reader. */
function clock(at: string): string {
  return at.slice(11, 16);
}

/** The text a byte range covers, shortened, for showing what moved. */
function excerpt(body: string | undefined, from: number, to: number): string {
  if (body === undefined) return `bytes ${from}-${to}`;
  const bytes = new TextEncoder().encode(body);
  const text = new TextDecoder().decode(bytes.slice(from, Math.min(to, bytes.length)));
  return text.length > 48 ? `${text.slice(0, 45)}...` : text;
}

/** The last few characters, which is where the forgery is. */
function tail(v: string): string {
  return v.length <= 12 ? v : `...${v.slice(-12)}`;
}

/** Changes the final character to a different one in the same alphabet. */
function flipLast(v: string): string {
  if (v.length === 0) return "A";
  const last = v[v.length - 1];
  const next = last === "A" ? "B" : "A";
  return v.slice(0, -1) + next;
}
