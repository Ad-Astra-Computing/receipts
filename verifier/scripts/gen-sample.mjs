// Regenerates the hero sample receipt with a realistic, multi-checkpoint
// composition timeline. Produces a valid folio.receipts/1 bundle: the
// timeline chain (SPEC section 5) and the Ed25519 bundle signature
// (SPEC section 6) are computed exactly as the verifier recomputes them,
// so the output passes verify.ts. Run: node scripts/gen-sample.mjs
//
// A fresh demo keypair is generated each run; the bundle is
// self-describing (it carries its own public key), so the verifier
// trusts whatever key signed it. This is a demo receipt, not a claim
// about a real author.

import { webcrypto as crypto } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const enc = new TextEncoder();
const here = (p) => fileURLToPath(new URL(p, import.meta.url));

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}
async function sha256hex(s) {
  return toHex(await sha256(enc.encode(s)));
}
function toHex(b) {
  let out = "";
  for (const x of b) out += x.toString(16).padStart(2, "0");
  return out;
}
function b64url(bytes) {
  return Buffer.from(bytes).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// The published body stays fixed: its sha256, the C2PA credential and
// the disclosed AI range all depend on it, and the verifier checks the
// body hash. We only rewrite the timeline.
const current = JSON.parse(readFileSync(here("../src/sample.receipts.json"), "utf8"));
const body = current.body;
const bundle = current.bundle;

// A realistic composition: the writer opens a draft, builds it up over a
// couple of sessions with a plateau while thinking, cuts a paragraph
// that did not work (the dip), then tightens to the final 49 words. Each
// checkpoint is a real autosave: a timestamp, running word and character
// counts, and a content hash of that draft state.
const base = Date.parse("2026-07-18T09:12:00Z");
const min = 60 * 1000;
const steps = [
  { t: 0, words: 6, chars: 34 },
  { t: 3, words: 21, chars: 118 },
  { t: 7, words: 38, chars: 213 },
  { t: 12, words: 44, chars: 247 },
  { t: 14, words: 44, chars: 247 }, // plateau: thinking, no net change
  { t: 19, words: 63, chars: 351 },
  { t: 26, words: 81, chars: 452 },
  { t: 34, words: 79, chars: 441 }, // small trim
  { t: 51, words: 58, chars: 324 }, // cut a paragraph that did not work
  { t: 63, words: 66, chars: 369 },
  { t: 78, words: 71, chars: 398 },
  { t: 92, words: 54, chars: 302 }, // tighten
  { t: 105, words: 51, chars: 286 },
  { t: 118, words: 49, chars: 261 }, // final: matches the published prose
];

const checkpoints = [];
for (let i = 0; i < steps.length; i++) {
  const s = steps[i];
  const at = new Date(base + s.t * min).toISOString().replace(/\.\d{3}Z$/, "Z");
  // Content hash of this draft state. Real Folio hashes the draft text;
  // here we hash a stable per-checkpoint marker so the sample is
  // deterministic without embedding intermediate drafts.
  const hash = await sha256hex(`folio.sample.checkpoint/${i}/${s.words}/${s.chars}`);
  checkpoints.push({ at, words: s.words, chars: s.chars, hash });
}

// Timeline chain, SPEC section 5.
let chain = "";
for (const cp of checkpoints) {
  chain = await sha256hex(`${chain}|${cp.at}|${cp.words}|${cp.chars}|${cp.hash}`);
}
bundle.timeline = { checkpoints, chain_hash: chain };

// Fresh demo keypair.
const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
const pubB64 = b64url(rawPub);

// Re-sign the credential with the new key so its signature.value is a
// real signature over the credential (minus its own signature field).
// The verifier binds this value into the bundle digest; keeping it a
// genuine signature keeps the sample internally honest.
const credForSig = { ...bundle.credential };
delete credForSig.signature;
const credDigest = await sha256(enc.encode("folio.c2pa.sig.v1" + JSON.stringify(credForSig)));
const credSig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, credDigest));
bundle.credential.signature = { alg: "Ed25519", public_key: pubB64, value: b64url(credSig) };

// Bundle signing digest, SPEC section 6.
async function signingDigest(b) {
  const parts = [];
  const add = async (s) => parts.push(await sha256(enc.encode(s)));
  await add("folio.receipts.sig.v1");
  await add(b.schema);
  await add(b.generated);
  await add(b.post.title ?? "");
  await add(b.post.url ?? "");
  await add(b.post.sha256);
  await add(b.credential.signature.value);
  await add(b.timeline.chain_hash);
  const ai = b.ai_ranges ?? [];
  await add(String(ai.length));
  for (const r of ai) {
    await add(`${r.from},${r.to}`);
    await add(r.model ?? "");
    await add(r.when ?? "");
  }
  const claims = b.claims ?? [];
  await add(String(claims.length));
  for (const c of claims) {
    await add(c.excerpt);
    await add(c.source_url);
    await add(c.status ?? "");
  }
  const total = parts.reduce((n, p) => n + p.length, 0);
  const buf = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    buf.set(p, o);
    o += p.length;
  }
  return sha256(buf);
}

const digest = await signingDigest(bundle);
const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, digest));
bundle.signature = { alg: "Ed25519", public_key: pubB64, value: b64url(sig) };

const out = JSON.stringify({ body, bundle }, null, 2) + "\n";
writeFileSync(here("../src/sample.receipts.json"), out);
writeFileSync(here("../public/sample.receipts.json"), out);
console.log(`Wrote sample with ${checkpoints.length} checkpoints, chain ${chain.slice(0, 12)}...`);
