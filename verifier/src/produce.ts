// SPDX-License-Identifier: Apache-2.0
//
// A producer, in TypeScript, for one purpose: proving that the two
// implementations agree on what a valid receipt is.
//
// The interop gate ran one way. Go signed a bundle and the browser
// verifier checked it, which proves the browser accepts what Go
// produces and says nothing about the reverse. A disagreement in the
// other direction, where TypeScript emits something Go refuses, would
// have gone unnoticed: it is exactly the shape of bug that only appears
// once somebody writes a producer in the other language, which is a
// thing the specification invites people to do.
//
// This is not shipped to the page and is not a general-purpose signing
// library. It builds one bundle, the smallest that exercises every
// signed field, using the SAME digest definitions the verifier
// enforces, imported rather than copied so they cannot drift.

import {
  signingDigest,
  credentialDigest,
  recomputeChain,
  type Bundle,
  type Credential,
} from "./verify";

const enc = new TextEncoder();

function bytesToB64url(b: Uint8Array): string {
  let s = "";
  for (const byte of b) s += String.fromCharCode(byte);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

async function sha256hex(text: string): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(text))));
}

export interface Produced {
  readonly bundle: Bundle;
  readonly body: string;
}

/**
 * Build and sign one bundle over `body`. A fresh keypair every call, so
 * the fixture is self-verifying and is not a claim about any author.
 */
export async function produceSignedBundle(body: string): Promise<Produced> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const publicKey = bytesToB64url(rawPub);
  const sign = async (bytes: Uint8Array): Promise<string> =>
    bytesToB64url(
      new Uint8Array(
        await crypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, bytes as BufferSource),
      ),
    );

  const bodyBytes = enc.encode(body);
  const assetHash = await sha256hex(body);
  const generated = "2026-08-19T00:00:00Z";

  const credential = {
    "@context": "https://c2pa.org/ns/manifest/1.4",
    type: "ContentCredential",
    asset: { sha256: assetHash, size: bodyBytes.length, mime: "text/markdown" },
    claim_generator: "receipts-interop/0.1.0",
    claim_generator_info: { name: "receipts-interop", version: "0.1.0" },
    created_at: generated,
    assertions: [{ label: "folio.interop", data: { produced_by: "typescript" } }],
    signature: { alg: "Ed25519", public_key: publicKey, value: "" },
  } as unknown as Credential;
  credential.signature.value = await sign(await credentialDigest(credential));

  const checkpoints = [
    { at: "2026-08-18T09:00:00Z", words: 3, chars: 18, hash: "a".repeat(64) },
    { at: "2026-08-18T09:30:00Z", words: 9, chars: 52, hash: "b".repeat(64) },
  ];

  const bundle = {
    schema: "folio.receipts/1",
    generated,
    post: {
      title: "Signed in TypeScript",
      url: "https://blog.example.com/post/signed-in-typescript/",
      sha256: assetHash,
    },
    credential,
    ai_ranges: [{ from: 4, to: 10, model: "claude-opus-4-8", when: generated }],
    claims: [{ excerpt: "a sourced sentence", source_url: "https://example.org/source" }],
    // recomputeChain, not a second implementation of it. The first
    // draft of this file wrote its own and got the separators wrong,
    // which is precisely the drift this whole exercise is about.
    timeline: { checkpoints, chain_hash: await recomputeChain({ checkpoints } as never) },
    signature: { alg: "Ed25519", public_key: publicKey, value: "" },
  } as unknown as Bundle;
  bundle.signature.value = await sign(await signingDigest(bundle));

  return { bundle, body };
}
