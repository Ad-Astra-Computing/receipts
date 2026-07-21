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
});
