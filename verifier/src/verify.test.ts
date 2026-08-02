// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { verifyBundle, recomputeChain, type Bundle } from "./verify";

// The fixture is a real Ed25519-signed bundle plus its post body,
// signed by a conforming producer. If the verifier's signing digest or
// timeline chain diverge from the format in SPEC.md, verification of
// this genuine bundle fails here.
// RECEIPTS_FIXTURE points the suite at a bundle generated elsewhere,
// which is how the Go module's interop test runs these checks against a
// freshly Go-signed bundle. Unset, the committed fixture is used.
const fixturePath =
  process.env.RECEIPTS_FIXTURE ??
  fileURLToPath(new URL("./testdata/sample-bundle.json", import.meta.url));

const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as {
  bundle: Bundle;
  body: string;
};

describe("verifyBundle against a Go-signed fixture", () => {
  it("verifies a genuine bundle with the correct body", async () => {
    const res = await verifyBundle(fixture.bundle, fixture.body);
    for (const c of res.checks) {
      expect(c.ok, `${c.name}: ${c.detail ?? ""}`).toBe(true);
    }
    expect(res.ok).toBe(true);
    expect(res.fingerprint).toMatch(/^[0-9a-f]{16}$/);
  });

  it("rejects a tampered body", async () => {
    const res = await verifyBundle(fixture.bundle, fixture.body + " tampered");
    expect(res.ok).toBe(false);
    expect(res.checks.find((c) => c.name.includes("Bundled text"))?.ok).toBe(false);
  });

  it("rejects a mutated post title (signature break)", async () => {
    const b = structuredClone(fixture.bundle);
    b.post.title = "A Different Title";
    const res = await verifyBundle(b, fixture.body);
    expect(res.ok).toBe(false);
    expect(res.checks.find((c) => c.name.includes("signature"))?.ok).toBe(false);
  });

  it("rejects a reordered timeline", async () => {
    const b = structuredClone(fixture.bundle);
    const cps = b.timeline.checkpoints ?? [];
    if (cps.length >= 2) {
      [cps[0], cps[1]] = [cps[1], cps[0]];
      const res = await verifyBundle(b, fixture.body);
      expect(res.checks.find((c) => c.name.includes("chain"))?.ok).toBe(false);
    }
  });

  it("rejects a mutated credential content field with signature.value unchanged", async () => {
    const b = structuredClone(fixture.bundle);
    (b.credential.asset as { sha256: string }).sha256 = "d".repeat(64);
    const res = await verifyBundle(b, fixture.body);
    expect(res.ok).toBe(false);
    expect(res.checks.find((c) => c.name === "Content credential valid")?.ok).toBe(false);
  });

  it("recomputes the timeline chain to the stored value", async () => {
    const chain = await recomputeChain(fixture.bundle.timeline);
    expect(chain).toBe(fixture.bundle.timeline.chain_hash);
  });

  it("has at least one timeline checkpoint and the AI range", async () => {
    expect((fixture.bundle.timeline.checkpoints ?? []).length).toBeGreaterThan(0);
    expect((fixture.bundle.ai_ranges ?? []).length).toBeGreaterThan(0);
  });
});
