// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { verifyBundle, type Bundle } from "./verify";

const load = () => JSON.parse(
  readFileSync(fileURLToPath(new URL("./sample.receipts.json", import.meta.url)), "utf8")
) as { body: string; bundle: Bundle };

const passed = (r: Awaited<ReturnType<typeof verifyBundle>>) => r.ok;

describe("adversarial: the verifier must REJECT tampering", () => {
  it("accepts the genuine sample (control)", async () => {
    const { bundle, body } = load();
    expect(passed(await verifyBundle(bundle, body))).toBe(true);
  });

  it("rejects a flipped body byte (text does not match hash)", async () => {
    const { bundle, body } = load();
    const r = await verifyBundle(bundle, body.replace("clean draft", "dirty draft"));
    expect(passed(r)).toBe(false);
    expect(r.checks.find(c => c.name.includes("matches"))?.ok).toBe(false);
  });

  it("rejects an edited AI range (signed field changed)", async () => {
    const { bundle, body } = load();
    const t = structuredClone(bundle);
    t.ai_ranges = [{ from: 0, to: 300, model: "evil" }];
    expect(passed(await verifyBundle(t, body))).toBe(false);
  });

  it("rejects a reordered timeline (chain broken)", async () => {
    const { bundle, body } = load();
    const t = structuredClone(bundle);
    const cps = t.timeline.checkpoints!;
    [cps[0], cps[1]] = [cps[1], cps[0]];
    const r = await verifyBundle(t, body);
    expect(passed(r)).toBe(false);
    expect(r.checks.find(c => c.name.includes("Timeline"))?.ok).toBe(false);
  });

  it("rejects an attacker re-signing with their OWN key over a changed body", async () => {
    // Attacker swaps in a new keypair + new post.sha256. The chain and
    // their own signature can be made internally consistent, but the
    // body-hash check ties it to the REAL published text.
    const { bundle, body } = load();
    const t = structuredClone(bundle);
    t.post.sha256 = "0".repeat(64); // claim a different body
    // even if signature somehow matched, body check must fail:
    expect(passed(await verifyBundle(t, body))).toBe(false);
  });

  it("rejects a truncated/garbage signature without throwing", async () => {
    const { bundle, body } = load();
    const t = structuredClone(bundle);
    t.signature.value = "not-base64!!!";
    const r = await verifyBundle(t, body); // must not throw
    expect(passed(r)).toBe(false);
  });

  it("does not throw on a missing timeline / empty bundle shape", async () => {
    const r = await verifyBundle({ schema: "folio.receipts/1", signature: { alg: "Ed25519", public_key: "", value: "" }, post: { sha256: "" }, timeline: { checkpoints: [], chain_hash: "" } } as unknown as Bundle);
    expect(passed(r)).toBe(false);
  });

  it("rejects an unknown schema", async () => {
    const { bundle, body } = load();
    const t = structuredClone(bundle);
    t.schema = "folio.receipts/99";
    expect(passed(await verifyBundle(t, body))).toBe(false);
  });

  // The core fix: an attacker holding a genuine bundle rewrites content
  // fields INSIDE the credential while leaving credential.signature.value
  // untouched. The outer digest only binds signature.value, so before the
  // inner-signature check these all showed green. They must now fail the
  // "Content credential valid" check.
  const credCheck = (r: Awaited<ReturnType<typeof verifyBundle>>) =>
    r.checks.find((c) => c.name === "Content credential valid");

  it("rejects a mutated credential asset.sha256 (value unchanged)", async () => {
    const { bundle, body } = load();
    const t = structuredClone(bundle);
    (t.credential.asset as { sha256: string }).sha256 = "f".repeat(64);
    const r = await verifyBundle(t, body);
    expect(passed(r)).toBe(false);
    expect(credCheck(r)?.ok).toBe(false);
  });

  it("rejects a mutated credential created_at (value unchanged)", async () => {
    const { bundle, body } = load();
    const t = structuredClone(bundle);
    (t.credential as { created_at: string }).created_at = "1999-01-01T00:00:00Z";
    const r = await verifyBundle(t, body);
    expect(passed(r)).toBe(false);
    expect(credCheck(r)?.ok).toBe(false);
  });

  it("rejects a mutated credential claim_generator (value unchanged)", async () => {
    const { bundle, body } = load();
    const t = structuredClone(bundle);
    (t.credential as { claim_generator: string }).claim_generator = "Forged/9.9";
    const r = await verifyBundle(t, body);
    expect(passed(r)).toBe(false);
    expect(credCheck(r)?.ok).toBe(false);
  });

  it("rejects a swapped credential public_key (value unchanged)", async () => {
    const { bundle, body } = load();
    const t = structuredClone(bundle);
    // Flip one base64url character of the credential's own public key.
    const pk = t.credential.signature.public_key;
    t.credential.signature.public_key = pk[0] === "A" ? "B" + pk.slice(1) : "A" + pk.slice(1);
    const r = await verifyBundle(t, body);
    expect(passed(r)).toBe(false);
    expect(credCheck(r)?.ok).toBe(false);
  });

  it("rejects a mutated credential assertion (value unchanged)", async () => {
    const { bundle, body } = load();
    const t = structuredClone(bundle);
    const assertions = (t.credential as { assertions: unknown[] }).assertions;
    assertions.push({ label: "attacker.injected", data: { anything: true } });
    const r = await verifyBundle(t, body);
    expect(passed(r)).toBe(false);
    expect(credCheck(r)?.ok).toBe(false);
  });

  it("rejects a credential whose key differs from the bundle key", async () => {
    // Even if the credential is self-consistently re-signed, its author
    // key must equal the outer bundle key. Here we only detach it: the
    // signature no longer matches AND the binding fails.
    const { bundle, body } = load();
    const t = structuredClone(bundle);
    t.signature.public_key = "0".repeat(43); // outer key differs now
    const r = await verifyBundle(t, body);
    expect(passed(r)).toBe(false);
    expect(credCheck(r)?.ok).toBe(false);
  });

  it("does not throw on a garbage credential signature", async () => {
    const { bundle, body } = load();
    const t = structuredClone(bundle);
    t.credential.signature.value = "not-base64!!!";
    const r = await verifyBundle(t, body); // must not throw
    expect(passed(r)).toBe(false);
    expect(credCheck(r)?.ok).toBe(false);
  });

  it("keeps the genuine sample fully valid including the credential", async () => {
    const { bundle, body } = load();
    const r = await verifyBundle(bundle, body);
    expect(passed(r)).toBe(true);
    expect(credCheck(r)?.ok).toBe(true);
  });
});
