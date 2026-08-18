// SPDX-License-Identifier: Apache-2.0
// Client-side verification of a Folio receipts bundle.
//
// This implements the signing digest and the timeline chain from
// SPEC.md (sections 5 and 6), so a reader's browser can verify a bundle
// with only WebCrypto: once this code has loaded, the verification
// itself consults no server. (You still trust whoever served this page
// to have delivered this code faithfully.) If the field order or
// separators here diverge from the specification, the test suite
// (verify.test.ts) fails against a genuine signed fixture.

import { canonicalize } from "./jcs";

export interface Signature {
  alg: string;
  public_key: string;
  value: string;
}
export interface PostRef {
  title?: string;
  url?: string;
  sha256: string;
}
export interface AIRange {
  from: number;
  to: number;
  model?: string;
  when?: string;
}
export interface ClaimRef {
  excerpt: string;
  source_url: string;
  status?: string;
}
export interface Checkpoint {
  at: string;
  words: number;
  chars: number;
  hash: string;
}
export interface TimelineDigest {
  checkpoints: Checkpoint[] | null;
  chain_hash: string;
}
export interface Credential {
  signature: Signature;
  [k: string]: unknown;
}
export interface Bundle {
  schema: string;
  generated: string;
  post: PostRef;
  credential: Credential;
  ai_ranges: AIRange[] | null;
  claims: ClaimRef[] | null;
  timeline: TimelineDigest;
  signature: Signature;
}

export const SCHEMA = "folio.receipts/1";

// SPEC.md section 4: RFC 3339, UTC, whole seconds, Z designator. The
// timeline chain and the signing digest both hash these as strings, so
// the spelling is part of the format rather than a display choice. Go
// refuses a bundle spelled any other way at parse; this is the same
// refusal on this side.
const CANONICAL_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

export function isCanonicalTime(s: unknown): boolean {
  if (typeof s !== "string" || !CANONICAL_TIME.test(s)) return false;
  // The pattern admits 2026-02-31T25:00:00Z, which is not a date.
  const t = Date.parse(s);
  return Number.isFinite(t) && new Date(t).toISOString().replace(/\.\d{3}Z$/, "Z") === s;
}

const enc = new TextEncoder();

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource));
}

async function sha256hex(s: string): Promise<string> {
  return toHex(await sha256(enc.encode(s)));
}

function toHex(b: Uint8Array): string {
  let out = "";
  for (const x of b) out += x.toString(16).padStart(2, "0");
  return out;
}

// SPEC.md section 3: unpadded base64url. atob is far more forgiving than
// that, accepting padding and the standard +/ alphabet, so a signature
// re-spelled either way decodes to the same bytes and verifies here while
// Go's RawURLEncoding refuses it. Same bundle, two verdicts. Reject the
// spelling, not just the bytes.
const B64URL = /^[A-Za-z0-9_-]+$/;

export function isCanonicalB64url(s: unknown): boolean {
  // Unpadded base64url is never 1 mod 4 characters long: that length
  // cannot be produced by encoding any byte string.
  if (typeof s !== "string" || s.length === 0 || s.length % 4 === 1 || !B64URL.test(s)) {
    return false;
  }
  // Alphabet and length are not enough. The final character of a 2 or 3
  // mod 4 string carries unused low bits, and a decoder ignores them, so
  // several different strings decode to the same key or signature. Go's
  // RawURLEncoding.Strict refuses those; the round trip is the same test
  // without hand-decoding the last sextet.
  try {
    const bytes = rawB64urlToBytes(s);
    return bytesToB64url(bytes) === s;
  } catch {
    return false;
  }
}

function bytesToB64url(b: Uint8Array): string {
  let bin = "";
  for (const x of b) bin += String.fromCharCode(x);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decodes without the canonical check, for use by that check itself. */
function rawB64urlToBytes(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlToBytes(s: string): Uint8Array {
  if (!isCanonicalB64url(s)) {
    throw new Error("value is not unpadded base64url");
  }
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// The signing digest, per SPEC.md section 6.
async function signingDigest(b: Bundle): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  const add = async (s: string) => {
    parts.push(await sha256(enc.encode(s)));
  };
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

// The embedded C2PA credential's own signing digest, per SPEC.md
// section 7. The signed payload is the credential with ONLY
// signature.value removed (signature.alg and signature.public_key stay
// covered), canonicalized with RFC 8785 JCS and prefixed with a domain
// tag so this signature can never be replayed against another payload.
//
//   credDigest = SHA-256( UTF8("folio.c2pa.sig.v1") || UTF8(JCS(cred')) )
//
// where cred' is a deep copy of the credential with signature.value
// deleted.
export const CRED_SIG_TAG = "folio.c2pa.sig.v1";

async function credentialDigest(cred: Credential): Promise<Uint8Array> {
  const copy = structuredClone(cred) as {
    signature?: { value?: unknown };
    [k: string]: unknown;
  };
  if (copy.signature && typeof copy.signature === "object") {
    delete copy.signature.value;
  }
  const canonical = canonicalize(copy);
  return sha256(enc.encode(CRED_SIG_TAG + canonical));
}

// A shared Ed25519 verify helper. Rejects any algorithm other than
// Ed25519 and any key or signature of the wrong raw length, so a
// truncated or oversized value can never slip past as "verified".
async function ed25519Verify(
  alg: string,
  publicKeyB64: string,
  sigB64: string,
  message: Uint8Array,
): Promise<boolean> {
  if (alg !== "Ed25519") return false;
  const pub = b64urlToBytes(publicKeyB64);
  const sig = b64urlToBytes(sigB64);
  if (pub.length !== 32 || sig.length !== 64) return false;
  const key = await crypto.subtle.importKey(
    "raw",
    pub as BufferSource,
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    { name: "Ed25519" },
    key,
    sig as BufferSource,
    message as BufferSource,
  );
}

// The timeline chain, per SPEC.md section 5.
export async function recomputeChain(t: TimelineDigest): Promise<string> {
  let prev = "";
  for (const cp of t.checkpoints ?? []) {
    prev = await sha256hex(`${prev}|${cp.at}|${cp.words}|${cp.chars}|${cp.hash}`);
  }
  return prev;
}

export interface Check {
  name: string;
  ok: boolean;
  detail?: string;
}
export interface VerifyResult {
  ok: boolean;
  checks: Check[];
  fingerprint: string; // short hex of the signing public key
}

// verifyBundle runs every check. When body is supplied, it also
// confirms the bundle describes that exact published body.
/**
 * Verifies a bundle. Total over ANY input: this runs on a public page
 * where the file comes from a stranger, so a malformed or hostile
 * document has to come back as a failed check, never as a thrown
 * exception. A thrown exception is an unhandled rejection and a page
 * that looks broken, which reads as "the verifier is broken" rather
 * than "this receipt is not valid".
 *
 * Structure is therefore established BEFORE anything is hashed, and the
 * whole body is wrapped as a fail-closed backstop for anything the
 * structural pass did not anticipate.
 */
export async function verifyBundle(input: unknown, body?: string): Promise<VerifyResult> {
  try {
    return await verifyBundleInner(input, body);
  } catch (e) {
    return {
      ok: false,
      checks: [{
        name: "Readable as a receipt",
        ok: false,
        detail: `this file could not be read as a receipt: ${e instanceof Error ? e.message : String(e)}`,
      }],
      fingerprint: "",
    };
  }
}

/** True when v is a plain object, which is what every nested field must be. */
function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// The members schema 1 defines, per SPEC section 3. A producer that adds
// anything else is adding content the signature does not cover, which Go
// refuses at parse, so this side refuses it too.
const MEMBERS: Record<string, readonly string[]> = {
  "": ["schema", "generated", "post", "credential", "ai_ranges", "claims", "timeline", "signature"],
  post: ["title", "url", "sha256"],
  timeline: ["checkpoints", "chain_hash"],
  checkpoint: ["at", "words", "chars", "hash"],
  ai_range: ["from", "to", "model", "when"],
  claim: ["excerpt", "source_url", "status"],
  signature: ["alg", "public_key", "value"],
};

function unknownMembers(o: unknown, allowed: readonly string[], where: string): string[] {
  if (!isObject(o)) return [];
  return Object.keys(o)
    .filter((k) => !allowed.includes(k))
    .map((k) => (where ? `${where}.${k}` : k));
}

/**
 * Names the structural problems that stop verification being meaningful.
 * Empty means the document has the shape the format defines, so the
 * cryptographic checks below are checking something real.
 */
function structuralProblems(b: unknown): string[] {
  if (!isObject(b)) return ["the file is not a JSON object"];
  const p: string[] = [];
  if (!isObject(b.post)) p.push("post");
  if (!isObject(b.credential)) p.push("credential");
  if (!isObject(b.signature)) p.push("signature");
  if (!isObject(b.timeline)) {
    p.push("timeline");
  } else {
    const cps = (b.timeline as Record<string, unknown>).checkpoints;
    if (!Array.isArray(cps)) p.push("timeline.checkpoints");
    else if (!cps.every(isObject)) p.push("timeline.checkpoints entries");
  }
  for (const name of ["ai_ranges", "claims"] as const) {
    const v = b[name];
    if (v === undefined || v === null) continue;
    if (!Array.isArray(v)) p.push(name);
    else if (!v.every(isObject)) p.push(`${name} entries`);
  }
  return p;
}

async function verifyBundleInner(input: unknown, body?: string): Promise<VerifyResult> {
  const checks: Check[] = [];

  const problems = structuralProblems(input);
  if (problems.length > 0) {
    checks.push({
      name: "Readable as a receipt",
      ok: false,
      detail: `not shaped like a receipt: ${problems.join(", ")}`,
    });
    return { ok: false, checks, fingerprint: "" };
  }
  const b = input as Bundle;

  // The credential is deliberately exempt: it is a C2PA-aligned object
  // whose own signature covers every member it carries, including ones
  // this format does not model, so an unknown member there is signed.
  const strays = [
    ...unknownMembers(b, MEMBERS[""], ""),
    ...unknownMembers(b.post, MEMBERS.post, "post"),
    ...unknownMembers(b.timeline, MEMBERS.timeline, "timeline"),
    ...unknownMembers(b.signature, MEMBERS.signature, "signature"),
    ...(b.timeline?.checkpoints ?? []).flatMap((cp, i) =>
      unknownMembers(cp, MEMBERS.checkpoint, `timeline.checkpoints[${i}]`)),
    ...(b.ai_ranges ?? []).flatMap((r, i) => unknownMembers(r, MEMBERS.ai_range, `ai_ranges[${i}]`)),
    ...(b.claims ?? []).flatMap((c, i) => unknownMembers(c, MEMBERS.claim, `claims[${i}]`)),
  ];
  checks.push({
    name: "Only signed fields present",
    ok: strays.length === 0,
    detail: strays.length === 0
      ? undefined
      : `carries content the signature does not cover: ${strays.join(", ")}`,
  });

  checks.push({ name: "Schema recognised", ok: b.schema === SCHEMA });

  // Before any hashing: is this bundle written in the one wire form the
  // format defines? Every hash below is over rendered strings, so a
  // bundle spelled differently would be checked against text no other
  // implementation would produce.
  const wireProblems: string[] = [];
  if (!isCanonicalTime(b.generated)) wireProblems.push("generated");
  for (const [i, cp] of (b.timeline?.checkpoints ?? []).entries()) {
    if (!isCanonicalTime(cp?.at)) wireProblems.push(`timeline.checkpoints[${i}].at`);
  }
  for (const [i, r] of (b.ai_ranges ?? []).entries()) {
    if (r?.when !== undefined && r.when !== null && !isCanonicalTime(r.when)) {
      wireProblems.push(`ai_ranges[${i}].when`);
    }
  }
  // Go refuses a non-canonical credential.created_at at parse, so this
  // side has to as well, or a credential with an offset timestamp passes
  // here and fails there.
  const createdAt = (b.credential as Record<string, unknown> | undefined)?.created_at;
  if (createdAt !== undefined && !isCanonicalTime(createdAt)) {
    wireProblems.push("credential.created_at");
  }
  for (const [label, sig] of [
    ["signature", b.signature],
    ["credential.signature", b.credential?.signature],
  ] as const) {
    if (!isCanonicalB64url(sig?.public_key)) wireProblems.push(`${label}.public_key`);
    if (!isCanonicalB64url(sig?.value)) wireProblems.push(`${label}.value`);
  }
  checks.push({
    name: "Wire forms canonical",
    ok: wireProblems.length === 0,
    detail: wireProblems.length === 0
      ? undefined
      : `not in the form the format requires: ${wireProblems.join(", ")}`,
  });

  let sigOk = false;
  try {
    sigOk = await ed25519Verify(
      b.signature.alg,
      b.signature.public_key,
      b.signature.value,
      await signingDigest(b),
    );
  } catch {
    sigOk = false;
  }
  checks.push({
    name: "Receipt signature valid",
    ok: sigOk,
    detail: sigOk
      ? undefined
      : "the receipt was not signed by the key it names, or a signed field changed",
  });

  // The embedded C2PA credential must itself be signed, and must be
  // consistent with the outer bundle. Without this, an attacker holding
  // a genuine bundle could rewrite credential content fields (asset
  // hash, timestamps, claim generator, assertions, even the credential
  // public key) while leaving credential.signature.value untouched, and
  // every outer check would still pass. SPEC.md section 8 step 5.
  let credOk = false;
  let credDetail = "the content credential's signature or bindings did not verify";
  try {
    const cred = b.credential;
    const credSig = cred?.signature as Signature | undefined;
    if (!credSig || typeof credSig !== "object") {
      credDetail = "the content credential has no signature";
    } else {
      const sigVerified = await ed25519Verify(
        credSig.alg,
        credSig.public_key,
        credSig.value,
        await credentialDigest(cred),
      );
      // Consistency: the credential binds the same body and the same
      // author key as the outer bundle. The credential's asset.sha256
      // must equal post.sha256, and the credential's public key must be
      // the outer bundle's public key (one author identity signs both).
      // The outer PostRef carries no size or mime, so there is nothing
      // to compare those credential fields against and we do not invent
      // a value; if a future bundle gains those outer fields, add the
      // comparisons here.
      const asset = (cred as { asset?: Record<string, unknown> }).asset ?? {};
      const bindings: boolean[] = [
        sigVerified,
        asset.sha256 === b.post.sha256,
        credSig.public_key === b.signature.public_key,
      ];
      credOk = bindings.every((x) => x);
      if (credOk) credDetail = "";
      else if (sigVerified) {
        credDetail =
          "the content credential is signed but does not match the receipt it travels in";
      }
    }
  } catch {
    credOk = false;
  }
  checks.push({
    name: "Content credential valid",
    ok: credOk,
    detail: credOk ? undefined : credDetail,
  });

  const chain = await recomputeChain(b.timeline);
  checks.push({
    name: "Timeline chain intact",
    ok: chain === b.timeline.chain_hash,
    detail: chain === b.timeline.chain_hash ? undefined : "the checkpoints were reordered or edited after signing",
  });

  if (body !== undefined) {
    const h = await sha256hex(body);
    const ok = h === b.post.sha256;
    checks.push({
      name: "Bundled text matches the receipt",
      ok,
      detail: ok ? undefined : "the text in this bundle does not match its own hash",
    });
  }

  // Fingerprint: first 8 bytes of sha256 over the raw public key,
  // shown to the reader as a short, stable identifier for the signer.
  let fp = "";
  try {
    fp = toHex(await sha256(b64urlToBytes(b.signature.public_key))).slice(0, 16);
  } catch {
    fp = "";
  }
  return { ok: checks.every((c) => c.ok), checks, fingerprint: fp };
}
