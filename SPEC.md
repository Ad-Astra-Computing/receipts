# Receipts of Thought: bundle format and signing scheme

Version 1 (`folio.receipts/1`)

This document specifies the receipts bundle: a portable, signed record
of how a piece of writing was made. It is written so that anyone can
implement a producer or a verifier from this text alone. The reference
verifier ([`verifier/src/verify.ts`](verifier/src/verify.ts)) is
normative where this prose is ambiguous.

## 1. What a bundle asserts

A bundle asserts four things about a published piece of writing, and
signs them as a unit:

1. A reference to the published body: its title, its canonical URL and
   the SHA-256 of its bytes.
2. A C2PA-aligned content credential, itself signed, binding the same
   author identity to the same body.
3. The AI-authored spans the author chose to disclose, as character
   ranges with an optional model name and timestamp.
4. The factual claims the author sourced, as an excerpt, a source URL
   and a status.

It also carries a fifth element that is a digest, not a disclosure: a
tamper-evident record of the composition timeline. This is the design
decision the whole format turns on, so it gets its own section below.

## 2. The timeline is a digest, never the draft

The timeline records that a process happened and makes any later edit
to that record detectable. It does not publish the drafts.

Each checkpoint carries a timestamp, a word count, a character count
and a content hash. It never carries draft text. The checkpoints are
bound into a hash chain (section 5) so that reordering, inserting or
editing any checkpoint after signing changes the chain and fails
verification.

Publishing intermediate drafts would expose
material the author never chose to share, and would make the format
hostile to adopt. Full replay of the drafts stays local, in the tool
that produced the bundle. What travels with the published piece is
proof that the process occurred, not the process itself.

## 3. Bundle structure

A bundle is a single JSON object. Field names are exact and
lower-snake-case in the wire format.

```json
{
  "schema": "folio.receipts/1",
  "generated": "2026-07-20T14:03:00Z",
  "post": {
    "title": "optional",
    "url": "optional canonical URL",
    "sha256": "hex of the published body bytes"
  },
  "credential": { "...": "a signed, C2PA-aligned manifest, see section 7" },
  "ai_ranges": [
    { "from": 120, "to": 240, "model": "optional", "when": "optional RFC3339" }
  ],
  "claims": [
    { "excerpt": "...", "source_url": "https://...", "status": "optional" }
  ],
  "timeline": {
    "checkpoints": [
      { "at": "2026-07-20T13:00:00Z", "words": 40, "chars": 210, "hash": "..." }
    ],
    "chain_hash": "hex, see section 5"
  },
  "signature": {
    "alg": "Ed25519",
    "public_key": "base64url, unpadded, raw 32-byte key",
    "value": "base64url, unpadded, raw 64-byte signature"
  }
}
```

`ai_ranges` and `claims` MAY be empty arrays. A verifier MUST treat a
missing or `null` array as empty. Timestamps are RFC 3339 in UTC,
truncated to whole seconds and rendered with the `Z` designator, so that
their string form is reproducible byte for byte on any platform. A
producer MUST NOT emit sub-second precision or a numeric zone offset.
The signing digest hashes the rendered timestamp (section 6), so a
bundle whose wire timestamp differs from the string that was signed
verifies in one implementation and fails in another.

## 4. Encodings

- Hashes are lowercase hexadecimal.
- The public key and signature are base64url without padding
  (RFC 4648 §5, no trailing `=`).
- All strings are UTF-8. The signing input is built from UTF-8 bytes.

## 5. The timeline chain

The chain binds every checkpoint field into a running value so that a
verifier can detect any change to the digest. Starting from an empty
string, for each checkpoint in order:

```
chain = SHA-256-hex( prev + "|" + at + "|" + words + "|" + chars + "|" + hash )
```

where `at` is the RFC 3339 UTC timestamp, `words` and `chars` are
decimal integers with no leading zeros, and `hash` is the checkpoint
content hash. `prev` is the previous chain value, or the empty string
for the first checkpoint. The final value is `timeline.chain_hash`.

Field order and the `|` separator are part of the format. A verifier
that gets them wrong will reject valid bundles.

## 6. The signature

The signature is Ed25519 over a digest built to be reproducible in a
browser with nothing but SHA-256 and UTF-8 encoding. There is no JSON
canonicalization step, because JSON canonicalization is a source of
silent cross-implementation drift.

The digest is a SHA-256 over the concatenation of per-field SHA-256
hashes, in this fixed order. Define `add(s)` as "append the 32 bytes
of SHA-256 over the UTF-8 bytes of `s`":

```
add("folio.receipts.sig.v1")   // domain separation tag
add(schema)
add(generated)                 // RFC3339 UTC
add(post.title)                // "" if absent
add(post.url)                  // "" if absent
add(post.sha256)
add(credential.signature.value)   // binds the whole C2PA credential
add(timeline.chain_hash)          // binds the whole timeline
add(decimal count of ai_ranges)
for each ai_range in order:
    add("from,to")             // two decimal integers joined by a comma
    add(model)                 // "" if absent
    add(when)                  // "" if absent
add(decimal count of claims)
for each claim in order:
    add(excerpt)
    add(source_url)
    add(status)                // "" if absent
digest = SHA-256(all the appended bytes)
```

The signature value is `Ed25519-Sign(private_key, digest)`. Verifying
recomputes the digest and checks it against `signature.value` using the
raw public key in `signature.public_key`.

Because each field is hashed to a fixed 32 bytes before
concatenation, there is no delimiter-injection risk: no field value can
forge the boundary between fields. The domain tag `folio.receipts.sig.v1`
ensures a signature over a receipts bundle can never be replayed as a
signature over some other Ed25519 payload.

The signature covers the C2PA credential through the credential's own
signature value, and the whole timeline through its chain hash, so
those large structures are bound without re-listing every one of their
fields.

## 7. Relationship to C2PA

The `credential` field is a signed, C2PA-aligned content credential: it
follows C2PA's data model, and departs from C2PA's serialization and
trust model in the ways this section sets out. C2PA (the Coalition for
Content Provenance and Authenticity) is the industry standard for
binding provenance assertions to media, and is being standardized as
ISO/DIS 22144, a draft international standard. The receipts bundle does
not replace it. It carries the credential inside a wrapper that adds the
composition-process assertions C2PA does not model: the disclosed AI
ranges, the sourced claims and the tamper-evident timeline digest.

An implementation MUST NOT present this credential as a full C2PA
manifest, and MUST NOT claim conformance to the C2PA specification on
the strength of verifying one. The differences are:

- The assertion store is JSON. The full standard encodes it as CBOR.
- The signature is raw Ed25519 over RFC 8785 canonical JSON
  (section 7.1). The full standard signs with COSE_Sign1.
- Trust is anchored in the author's own public key, presented to the
  reader as a fingerprint. The full standard anchors trust in an X.509
  certificate chain validated against a C2PA trust list.
- Assertions labelled `c2pa.*` mirror the standard's labels where the
  data is meaningful. Assertions labelled `folio.*` are extensions
  defined by this specification, and no C2PA reader is required to
  understand them.

A general C2PA implementation therefore does not read this credential,
and a verifier conforming to this specification does not read a
COSE-signed C2PA manifest. The reason for the divergence is that
personal publishers have no certificate authority, while a self-anchored
public key fingerprint is verifiable by any reader with nothing but a
SHA-256 and an Ed25519 primitive.

The two signatures share one author identity. The same Ed25519 key that
signs the outer bundle signs the embedded credential, so a verifier
that trusts the author's key trusts both at once, and a reader sees a
single fingerprint.

### 7.1 Signing the credential

The credential carries its own `signature` object with the same shape
as the outer bundle signature (`alg`, `public_key`, `value`). Unlike the
outer bundle, the credential is a nested C2PA structure whose field set
grows over time, so its signing input is a canonical serialization of
the credential rather than a fixed field list.

The signed payload is the credential with only `signature.value`
removed. `signature.alg` and `signature.public_key` stay in the signed
payload, so the declared algorithm and the author key cannot be swapped
after signing. That payload is serialized with the JSON Canonicalization
Scheme (RFC 8785, JCS): object members are sorted by UTF-16 code-unit
order, array order is preserved, strings use standard JSON escaping with
no Unicode normalization, and numbers are the safe integers the
credential uses in plain JSON form. The reference verifier implements
this subset in [`verifier/src/jcs.ts`](verifier/src/jcs.ts) with no
external dependency, so the serializer is auditable.

The credential digest is:

```
credDigest = SHA-256( UTF8("folio.c2pa.sig.v1") || UTF8( JCS(credential without signature.value) ) )
```

`folio.c2pa.sig.v1` is a domain separation tag distinct from the bundle
tag `folio.receipts.sig.v1`, so a credential signature can never be
replayed as a bundle signature or the reverse. The credential's
`signature.value` is `Ed25519-Sign(private_key, credDigest)`, and the
credential public key MUST equal the outer bundle public key.

This covers every content field of the credential (asset hash, size,
mime, `claim_generator`, `created_at`, every assertion and the
credential's own algorithm and public key). The outer bundle digest
binds only `credential.signature.value` (section 6), so the credential's
own signature is what makes those content fields tamper-evident: without
verifying it, an attacker holding a genuine bundle could rewrite any
credential content field while leaving `credential.signature.value`
unchanged and still pass every outer check. A verifier MUST verify this
inner signature.

## 8. Verification obligations

A conforming verifier MUST, in order:

1. Reject any `schema` it does not recognise.
2. Reject any `signature.alg` other than `Ed25519`.
3. Reject a public key that is not 32 bytes or a signature that is not
   64 bytes after base64url decoding.
4. Recompute the signing digest (section 6) and reject a bundle whose
   `signature.value` does not verify against it.
5. Verify the embedded content credential. This has two parts, and any
   failure rejects the bundle:
   a. Recompute the credential digest (section 7.1) and verify
      `credential.signature.value` against it with the credential's
      public key. Reject a credential whose `signature.alg` is not
      `Ed25519`, whose public key is not 32 bytes, or whose signature is
      not 64 bytes after base64url decoding.
   b. Check the credential's bindings to the outer bundle:
      `credential.asset.sha256` MUST equal `post.sha256`, and
      `credential.signature.public_key` MUST equal
      `signature.public_key` (one author identity signs both). Where the
      credential declares an asset `size` or `mime` and the outer bundle
      carries the same field, they MUST agree; where the outer bundle has
      no such field, the verifier makes no comparison and invents no
      value.
6. Recompute the timeline chain (section 5) and reject a mismatch.

Step 5 MUST NOT be able to throw: malformed credential input rejects the
bundle rather than aborting verification.

When the verifier is also given the published body, it MUST additionally
confirm that the SHA-256 of the body equals `post.sha256`.

A verifier MUST NOT consult any network service to perform these
checks. Every input it needs is in the bundle and, optionally, the body.

## 9. What a valid bundle does and does not prove

A valid bundle proves that the described process, credential and body
have not been altered since they were signed by the named key, and that
they are consistent with one another. That is a claim about tamper
evidence and about one author identity.

It does not prove that a human, rather than an automated pipeline, sat
at the keyboard. No signing tool can prove intent. The value of the
format is a verifiable record of how a piece was made and disclosed,
checkable by anyone, trusting no server. Treat any stronger claim with
suspicion.

## 10. Versioning

The `schema` value carries the format version. A breaking change to any
field, encoding, chain construction or signing digest requires a new
schema string (`folio.receipts/2` and so on). Verifiers reject schemas
they do not recognise rather than guessing. The domain tag in the
signing digest is versioned independently (`folio.receipts.sig.v1`) and
moves only when the digest construction changes.
