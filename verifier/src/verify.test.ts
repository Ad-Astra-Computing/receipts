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

  it("refuses a body of a length the credential does not state", async () => {
    // The credential carries the body's byte length. On the genuine
    // fixture the check must exist and pass; with the number changed it
    // must fail on its own terms, so deleting the check fails here
    // rather than passing quietly.
    const good = await verifyBundle(fixture.bundle, fixture.body);
    const named = good.checks.find((c) => c.name.includes("length the credential states"));
    expect(named, "the declared-length check is missing").toBeDefined();
    expect(named?.ok).toBe(true);

    const b = structuredClone(fixture.bundle);
    (b.credential.asset as { size: number }).size += 1;
    const res = await verifyBundle(b, fixture.body);
    const wrong = res.checks.find((c) => c.name.includes("length the credential states"));
    expect(wrong?.ok).toBe(false);
    expect(wrong?.detail).toContain("bytes");
    expect(res.ok).toBe(false);
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

// SPEC.md section 4 fixes one wire form for every hashed timestamp, and
// section 3 requires unpadded base64url. The Go implementation refuses
// anything else at parse. This verifier has to agree, or the same bytes
// get two verdicts depending on who checks them, which is the one thing
// a format meant for independent verifiers cannot do.
function clone(): Bundle {
  return JSON.parse(JSON.stringify(fixture.bundle)) as Bundle;
}

describe("canonical wire forms", () => {
  // These must fail on their own named check, not merely because the
  // chain no longer matches. A bundle whose chain_hash was computed over
  // the non-canonical string is internally consistent to a verifier that
  // hashes the literal wire text, and Go now refuses such a bundle at
  // parse. If this verifier only noticed via the chain, the two would
  // still disagree on the bundles that matter.
  const canonicalCheck = (res: { checks: { name: string; ok: boolean }[] }) =>
    res.checks.find((c) => /canonical/i.test(c.name));

  it("rejects a checkpoint timestamp that is not whole-second UTC", async () => {
    for (const at of [
      "2026-01-01T05:00:00+05:00",
      "2026-01-01T00:00:00.5Z",
      "2026-01-01T00:00:00+00:00",
    ]) {
      const b = clone();
      b.timeline.checkpoints[0].at = at;
      const res = await verifyBundle(b);
      expect(canonicalCheck(res)?.ok, `accepted ${at}`).toBe(false);
      expect(res.ok).toBe(false);
    }
  });

  it("accepts the canonical form", async () => {
    const res = await verifyBundle(fixture.bundle, fixture.body);
    expect(canonicalCheck(res)?.ok).toBe(true);
  });

  it("rejects a generated timestamp that is not whole-second UTC", async () => {
    const b = clone();
    b.generated = "2026-01-01T00:00:00.250Z";
    const res = await verifyBundle(b);
    expect(canonicalCheck(res)?.ok).toBe(false);
  });

  it("rejects a signature re-encoded as padded or standard base64", async () => {
    const good = fixture.bundle.signature.value;
    for (const spelling of [good + "=", good.replace(/-/g, "+").replace(/_/g, "/")]) {
      if (spelling === good) continue;
      const b = clone();
      b.signature.value = spelling;
      const res = await verifyBundle(b);
      expect(canonicalCheck(res)?.ok, `accepted ${spelling.slice(-8)}`).toBe(false);
      expect(res.ok).toBe(false);
    }
  });
});


describe("unsigned members", () => {
  it("refuses a bundle carrying content the signature does not cover", async () => {
    for (const mutate of [
      (b: Bundle) => ((b as Record<string, unknown>).surprise = 1),
      (b: Bundle) => ((b.post as unknown as Record<string, unknown>).surprise = 1),
      (b: Bundle) => ((b.timeline.checkpoints[0] as unknown as Record<string, unknown>).surprise = 1),
      (b: Bundle) => ((b.signature as unknown as Record<string, unknown>).surprise = 1),
    ]) {
      const b = clone();
      mutate(b);
      const res = await verifyBundle(b);
      const check = res.checks.find((c) => c.name === "Only signed fields present");
      expect(check?.ok).toBe(false);
      expect(res.ok).toBe(false);
    }
  });

  it("accepts the fixture, which carries only defined members", async () => {
    const res = await verifyBundle(fixture.bundle, fixture.body);
    expect(res.checks.find((c) => c.name === "Only signed fields present")?.ok).toBe(true);
  });
});

describe("credential shape", () => {
  it("refuses a signed object that is not a content credential", async () => {
    for (const [what, mutate] of [
      ["@context", (c: Record<string, unknown>) => (c["@context"] = "https://example.com/x")],
      ["type", (c: Record<string, unknown>) => (c.type = "SomethingElse")],
      ["asset.sha256", (c: Record<string, unknown>) => ((c.asset as Record<string, unknown>).sha256 = "AA")],
      ["claim_generator", (c: Record<string, unknown>) => (c.claim_generator = "")],
      ["assertions", (c: Record<string, unknown>) => delete c.assertions],
    ] as const) {
      const b = clone();
      mutate(b.credential as unknown as Record<string, unknown>);
      const res = await verifyBundle(b);
      const check = res.checks.find((c) => c.name === "Content credential valid");
      expect(check?.ok, `accepted a credential with a broken ${what}`).toBe(false);
    }
  });
});
