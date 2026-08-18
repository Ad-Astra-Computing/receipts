// SPDX-License-Identifier: Apache-2.0
// @vitest-environment jsdom
//
// The renderer is browser code and had no DOM tests, which is how it
// kept a crash that verification had already been hardened against.
import { describe, it, expect } from "vitest";
import { renderReceipt } from "./render";
import { verifyBundle } from "./verify";

// verifyBundle returns a failure for anything; the renderer then has to
// survive the same input. Otherwise the page breaks on a dropped file,
// which is what a reader sees as "the verifier is broken".
describe("renderReceipt on documents that are not receipts", () => {
  for (const [name, input] of [
    ["an empty object", {}],
    ["null", null],
    ["a bundle with no post", { timeline: { checkpoints: [] } }],
    ["a bundle with no timeline", { post: { title: "t" } }],
    ["checkpoints not an array", { post: {}, timeline: { checkpoints: 3 } }],
  ] as const) {
    it(`renders a refusal instead of throwing: ${name}`, async () => {
      const res = await verifyBundle(input);
      expect(res.ok).toBe(false);
      const host = document.createElement("div");
      expect(() => renderReceipt(host, input as never, undefined, res)).not.toThrow();
      expect(host.textContent).toContain("Not a receipt");
    });
  }
});
