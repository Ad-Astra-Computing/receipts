// SPDX-License-Identifier: Apache-2.0
//
// Regenerates the hero sample receipt with a multi-checkpoint
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

// RFC 8785 JCS for the credential subset, mirroring src/jcs.ts. Objects
// sort keys by UTF-16 code-unit order, arrays keep their order, strings
// use standard JSON escaping with no Unicode normalization, and numbers
// are safe integers in JSON form. Kept in step with the verifier so the
// generated credential is internally valid against verify.ts.
function canonicalize(value) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "string") return JSON.stringify(value);
  if (t === "number") {
    if (!Number.isFinite(value)) throw new Error("jcs: non-finite number");
    return JSON.stringify(value);
  }
  if (t === "boolean") return value ? "true" : "false";
  if (t === "undefined") throw new Error("jcs: undefined is not serializable");
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  const keys = Object.keys(value).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const parts = [];
  for (const k of keys) {
    const v = value[k];
    if (v === undefined) throw new Error(`jcs: undefined value at key ${k}`);
    parts.push(JSON.stringify(k) + ":" + canonicalize(v));
  }
  return "{" + parts.join(",") + "}";
}

// The demo body. Its sha256 is recomputed below and written into both
// post.sha256 and the credential's asset, so editing this prose keeps
// the bundle internally consistent. The disclosed AI range is a
// character offset into this string: check it if you move text before
// the phrase "written with an AI".
const body =
  '+++\ntitle = "Keep the receipts"\n+++\n\n' +
  "When anyone can generate text, a clean draft proves nothing. What still counts is " +
  "the work behind it: the sources checked, the lines cut, and the parts written with " +
  "an AI assistant, disclosed and signed. This note carries one, so you can see what a " +
  "receipt looks like.\n";

const current = JSON.parse(readFileSync(here("../src/sample.receipts.json"), "utf8"));
const bundle = current.bundle;

const bodyHash = await sha256hex(body);
const bodySize = Buffer.byteLength(body);
bundle.post.sha256 = bodyHash;
bundle.credential.asset.sha256 = bodyHash;
bundle.credential.asset.size = bodySize;

// The timeline is constructed, not observed: this is a demonstration
// receipt, so the shape of a plausible composition is written out here
// rather than recorded from a real writing session. Every signature
// over it is genuine, so every check the verifier runs is a real check.
// The curve: a draft opened, built up over a couple of sessions with a
// plateau while thinking, a paragraph cut that did not work (the dip),
// then tightened. Each checkpoint carries a timestamp, running word and
// character counts, and a content hash of that draft state.
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
  { t: 118, words: 48, chars: 269 }, // final: matches the published prose above
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
// real signature over the credential (SPEC section 7). The signed
// payload is the credential with ONLY signature.value removed, so
// signature.alg and signature.public_key are covered. It is canonical-
// ized with JCS and prefixed with the domain tag, exactly as verify.ts
// recomputes it. The credential public key equals the bundle key: one
// author identity signs both.
bundle.credential.signature = { alg: "Ed25519", public_key: pubB64 };
const credForSig = structuredClone(bundle.credential);
delete credForSig.signature.value;
const credDigest = await sha256(enc.encode("folio.c2pa.sig.v1" + canonicalize(credForSig)));
const credSig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, credDigest));
bundle.credential.signature.value = b64url(credSig);

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
