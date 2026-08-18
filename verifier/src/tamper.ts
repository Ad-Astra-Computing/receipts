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
      const edited = text.includes("receipts")
        ? text.replace("receipts", "invoices")
        : `${text} (edited after signing)`;
      return { bundle: b, body: edited, note: "One word of the published text was changed." };
    }
    case "timeline": {
      // Make the work look different: swap two checkpoints so the draft
      // appears to have grown in another order.
      const cps = b.timeline?.checkpoints ?? [];
      if (cps.length >= 2) {
        const [first, second] = [cps[0], cps[1]];
        cps[0] = second;
        cps[1] = first;
      }
      return { bundle: b, body, note: "Two checkpoints were swapped, as if the drafts arrived in another order." };
    }
    case "range": {
      // Shrink a disclosure: claim less of the text was AI-written.
      const ranges = b.ai_ranges ?? [];
      if (ranges.length > 0) {
        ranges[0] = { ...ranges[0], to: Math.max(ranges[0].from + 1, ranges[0].to - 6) };
      }
      return { bundle: b, body, note: "A disclosed AI passage was made shorter than it was." };
    }
    case "signature": {
      // Sign it with someone else's key, or forge the value.
      const value = b.signature?.value ?? "";
      b.signature = { ...b.signature, value: flipLast(value) };
      return { bundle: b, body, note: "The signature was altered." };
    }
  }
}

/** Changes the final character to a different one in the same alphabet. */
function flipLast(v: string): string {
  if (v.length === 0) return "A";
  const last = v[v.length - 1];
  const next = last === "A" ? "B" : "A";
  return v.slice(0, -1) + next;
}
