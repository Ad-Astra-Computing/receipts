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

function b64urlToBytes(s: string): Uint8Array {
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
export async function verifyBundle(b: Bundle, body?: string): Promise<VerifyResult> {
  const checks: Check[] = [];

  checks.push({ name: "Schema recognised", ok: b.schema === SCHEMA });

  let sigOk = false;
  try {
    if (b.signature.alg !== "Ed25519") throw new Error("unsupported alg");
    const pub = b64urlToBytes(b.signature.public_key);
    const sig = b64urlToBytes(b.signature.value);
    const key = await crypto.subtle.importKey("raw", pub as BufferSource, { name: "Ed25519" }, false, ["verify"]);
    sigOk = await crypto.subtle.verify({ name: "Ed25519" }, key, sig as BufferSource, (await signingDigest(b)) as BufferSource);
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
