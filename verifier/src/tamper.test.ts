// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { tamper, type Tamper } from "./tamper";
import { verifyBundle, type Bundle } from "./verify";

const fixture = JSON.parse(
  readFileSync(fileURLToPath(new URL("./testdata/sample-bundle.json", import.meta.url)), "utf8"),
) as { bundle: Bundle; body: string };

// The demonstration is only worth anything if the failures are real: the
// same verifier, refusing for the reason shown, with nothing rigged.
describe("tamper", () => {
  it("starts from a receipt that verifies", async () => {
    const res = await verifyBundle(fixture.bundle, fixture.body);
    expect(res.ok).toBe(true);
  });

  for (const kind of ["body", "timeline", "range", "signature"] as Tamper[]) {
    it(`makes verification fail: ${kind}`, async () => {
      const t = tamper(kind, fixture.bundle, fixture.body);
      const res = await verifyBundle(t.bundle, t.body);
      expect(res.ok, `${kind} left the receipt verifying`).toBe(false);
      expect(t.note.length).toBeGreaterThan(0);
    });
  }

  it("leaves the original untouched", () => {
    const before = JSON.stringify(fixture.bundle);
    tamper("timeline", fixture.bundle, fixture.body);
    tamper("range", fixture.bundle, fixture.body);
    expect(JSON.stringify(fixture.bundle)).toBe(before);
  });

  it("fails the check a reader would expect", async () => {
    const failing = async (kind: Tamper) => {
      const t = tamper(kind, fixture.bundle, fixture.body);
      const res = await verifyBundle(t.bundle, t.body);
      return res.checks.filter((c) => !c.ok).map((c) => c.name);
    };
    expect(await failing("body")).toContain("Bundled text matches the receipt");
    expect(await failing("timeline")).toContain("Timeline chain intact");
    expect(await failing("signature")).toContain("Receipt signature valid");
  });
});

// Showing that something broke, without showing what changed, asks the
// reader for exactly the trust the receipt is meant to replace.
describe("what changed is shown", () => {
  for (const kind of ["body", "timeline", "range", "signature"] as Tamper[]) {
    it(`reports a before and an after: ${kind}`, () => {
      const t = tamper(kind, fixture.bundle, fixture.body);
      expect(t.before, `${kind} reported no before`).not.toBe("");
      expect(t.after, `${kind} reported no after`).not.toBe("");
      expect(t.before).not.toBe(t.after);
    });
  }

  it("names the word it replaced in the text", () => {
    const t = tamper("body", fixture.bundle, fixture.body);
    expect(fixture.body).toContain(t.before);
    expect(t.after).toBe("invoices");
  });
});
