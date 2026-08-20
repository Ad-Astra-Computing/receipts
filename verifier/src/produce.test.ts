// SPDX-License-Identifier: Apache-2.0
//
// The other half of the interop gate.
//
// Setting RECEIPTS_TS_FIXTURE makes this write a TypeScript-signed
// bundle to that path, which the Go suite then verifies. Without it,
// this still checks that what the producer emits satisfies the
// verifier, so a broken producer fails here rather than in a confusing
// cross-language failure.
import { describe, it, expect } from "vitest";
import { writeFileSync } from "node:fs";
import { produceSignedBundle } from "./produce";
import { verifyBundle } from "./verify";

describe("a bundle produced in TypeScript", () => {
  it("verifies under this verifier, and writes the fixture when asked", async () => {
    const { bundle, body } = await produceSignedBundle(
      "+++\ntitle = \"Signed in TypeScript\"\n+++\n\nThis body was signed by the browser implementation.\n",
    );
    const res = await verifyBundle(bundle, body);
    for (const c of res.checks) {
      expect(c.ok, `${c.name}: ${c.detail ?? ""}`).toBe(true);
    }
    expect(res.ok).toBe(true);

    const out = process.env.RECEIPTS_TS_FIXTURE;
    if (out) writeFileSync(out, JSON.stringify({ bundle, body }, null, 2));
  });

  it("produces a different key every time, so a fixture is never an identity claim", async () => {
    const a = await produceSignedBundle("one");
    const b = await produceSignedBundle("one");
    expect(a.bundle.signature.public_key).not.toBe(b.bundle.signature.public_key);
  });
});
