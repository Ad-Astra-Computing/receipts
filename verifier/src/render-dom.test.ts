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

describe("a receipt built to exhaust the reader's browser", () => {
  // A file a stranger hands you can carry tens of thousands of
  // checkpoints inside the 8 MiB cap. Verification still covers every
  // one; what must not happen is the tab freezing while the table is
  // built, or an engine argument limit being hit by a spread.
  const manyCheckpoints = (n: number) => ({
    post: { title: "t", url: "https://example.com/", sha256: "a".repeat(64) },
    timeline: {
      chain_hash: "b".repeat(64),
      checkpoints: Array.from({ length: n }, (_, i) => ({
        at: "2026-01-01T00:00:00Z",
        words: i % 97,
        chars: i,
        hash: "c".repeat(64),
      })),
    },
  });

  it("caps the rows it builds and says so, without claiming the rest went unchecked", async () => {
    const bundle = manyCheckpoints(5000);
    const res = await verifyBundle(bundle as never);
    const host = document.createElement("div");
    renderReceipt(host, bundle as never, undefined, res);
    const rows = host.querySelectorAll("tbody tr");
    expect(rows.length).toBeLessThanOrEqual(2000);
    expect(host.textContent).toMatch(/Showing the first 2000 of 5000 checkpoints/);
    expect(host.textContent).toMatch(/All 5000 were verified/);
  });

  it("survives a checkpoint count that would break a spread", async () => {
    // Math.max(1, ...words) throws RangeError around this size in V8.
    const bundle = manyCheckpoints(200000);
    const res = await verifyBundle(bundle as never);
    const host = document.createElement("div");
    expect(() => renderReceipt(host, bundle as never, undefined, res)).not.toThrow();
  });
});
