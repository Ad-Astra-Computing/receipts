# Receipts of Thought: bundle format and signing scheme

Version 1 (`folio.receipts/1`)

This document specifies the receipts bundle: a portable, signed record
of how a piece of writing was made. It is written so that anyone can
implement a producer or a verifier from this text alone.

This document is normative. The implementations in this repository, the
Go module and the TypeScript verifier, are references: where one of them
disagrees with this text, the implementation is wrong. Naming the code as
the tie-breaker, as an earlier version of this document did, made the
specification circular and left an independent implementer reading
TypeScript to learn the format.

Where this text is genuinely silent, that is a defect in it. Please
report it rather than reading the code, so the answer lands here and
every implementation gets it.

## 1. What a bundle asserts

A bundle asserts four things about a published piece of writing, and
signs them as a unit:

1. A reference to the published body: its title, its canonical URL and
   the SHA-256 of its bytes.
2. A C2PA-aligned content credential, itself signed, binding the same
   signing key to the same body.
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

### 3.1 Members, types and requiredness

The tables below are normative. "Integer" means a JSON number that is
integral and within the safe range of section 4. A verifier MUST reject a
member whose JSON type differs from the one given, rather than coercing
it: a language whose strings interpolate numbers and a language with a
typed decoder will otherwise disagree about the same document.

A bundle MUST contain no members other than those listed. Unknown members
are refused rather than ignored, because the signing digest of section 6
covers a fixed list, so anything else would be carried unsigned while the
receipt reports that nothing was altered. Extension belongs to a new
schema string, not to unsigned members of this one.

| Member | Type | Required | Rule |
| --- | --- | --- | --- |
| `schema` | string | yes | Exactly `folio.receipts/1`. |
| `generated` | string | yes | Canonical timestamp (section 4). |
| `post` | object | yes | See below. |
| `credential` | object | yes | See section 7. |
| `ai_ranges` | array or null | no | Absent or `null` means empty. |
| `claims` | array or null | no | Absent or `null` means empty. |
| `timeline` | object | yes | See below. A receipt whose subject is the composition record MUST carry one, even when empty. |
| `signature` | object | yes | See below. |

`post`:

| Member | Type | Required | Rule |
| --- | --- | --- | --- |
| `title` | string | no | Not otherwise constrained. |
| `url` | string | no | Not otherwise constrained. Verification establishes neither validity nor reachability. |
| `sha256` | string | yes | 64 lowercase hex characters: SHA-256 of the published body's UTF-8 bytes. |

`timeline`:

| Member | Type | Required | Rule |
| --- | --- | --- | --- |
| `checkpoints` | array | yes | MAY be empty. Each element is an object. |
| `chain_hash` | string | yes | The chain value of section 5. For an empty `checkpoints` this is the empty string. |

`timeline.checkpoints[]`:

| Member | Type | Required | Rule |
| --- | --- | --- | --- |
| `at` | string | yes | Canonical timestamp. Checkpoints SHOULD be in non-decreasing time order; a verifier does not enforce this, and MUST NOT present chain validity as evidence of it. |
| `words` | integer | yes | Non-negative. Section 3.2. |
| `chars` | integer | yes | Non-negative. Section 3.2. |
| `hash` | string | yes | 64 lowercase hex characters. Section 3.2. |

`ai_ranges[]`:

| Member | Type | Required | Rule |
| --- | --- | --- | --- |
| `from` | integer | yes | Non-negative UTF-8 byte offset into the published body. |
| `to` | integer | yes | Non-negative, and strictly greater than `from`. The range is half-open: `[from, to)`. |
| `model` | string | no | Free text. No registry of model names is defined, and a verifier MUST NOT treat this as attested. |
| `when` | string | no | If present, a canonical timestamp. The empty string is not a timestamp and MUST be rejected. |

A verifier MUST reject a negative, inverted or empty range. It cannot
check a range against the body when no body was supplied, so a bundle
whose ranges exceed the body length is rejected only when the body is
present (section 8).

`claims[]`:

| Member | Type | Required | Rule |
| --- | --- | --- | --- |
| `excerpt` | string | yes | The sentence being sourced. |
| `source_url` | string | yes | Not otherwise constrained. A receipt records that the author cited this source, and nothing about whether the source supports the claim. |
| `status` | string | no | Free text. This version defines no enumeration and a verifier MUST NOT infer one. |

`signature`:

| Member | Type | Required | Rule |
| --- | --- | --- | --- |
| `alg` | string | yes | Exactly `Ed25519`. This version defines no other algorithm. |
| `public_key` | string | yes | Canonical unpadded base64url of the raw 32-byte key (section 4). |
| `value` | string | yes | Canonical unpadded base64url of the raw 64-byte signature. |

### 3.2 Checkpoint counts and hash

A checkpoint describes one saved state of the draft. All three derived
values are computed from the draft text at that moment, and a third-party
producer MUST compute them the same way or its chain will not reproduce.

- `hash` is the SHA-256 of the draft text's UTF-8 bytes at that
  checkpoint, lowercase hex. The draft text itself never appears in the
  bundle; this is the only trace of it, and it is one-way.
- `chars` counts Unicode code points, not bytes and not grapheme
  clusters.
- `words` counts maximal non-empty runs of code points separated by any
  of exactly six characters: space (U+0020), tab (U+0009), line feed
  (U+000A), carriage return (U+000D), form feed (U+000C) and vertical tab
  (U+000B). No other character separates words, so punctuation attaches
  to the word it touches and a hyphenated compound counts as one.

  The list is deliberately closed and ASCII. "Unicode whitespace" would
  make the count depend on which version of which table an implementation
  consulted, and this number is hashed into the chain, so two producers
  that disagreed by one word would produce receipts that do not verify
  against each other. The cost is that a no-break space (U+00A0) or an
  ideographic space (U+3000) does not separate words, which undercounts
  text that uses them. That is a known limitation of this version, kept
  because an exactly reproducible count matters more here than a
  linguistically ideal one.

Because `hash` is over text a verifier never sees, it proves nothing on
its own. Its role is to bind each checkpoint into the chain of section 5,
so that a checkpoint cannot be altered, reordered or removed after
signing without detection.

### 3.3 Duplicate member names

A conforming producer MUST NOT emit an object with a duplicated member
name. Behaviour on receiving one is not defined by this version: JSON
parsers differ, typically taking either the first or the last, and two
verifiers may therefore disagree about such a document. A verifier
SHOULD reject a duplicate rather than choose.

## 3a. The transport envelope

A bundle is the root object of a `.receipts.json` file. That file alone
is enough to verify everything except one thing: whether the published
body still matches `post.sha256`. To check that, a verifier needs the
body, and a reader who was handed only a receipt does not have it.

So a producer MAY wrap a bundle for transport:

```json
{ "bundle": { ...the bundle... }, "body": "the published text" }
```

Rules:

- The envelope is NOT a bundle and is never signed. Nothing about it is
  covered by `signature`. Its only purpose is to carry a body alongside
  the receipt that describes it.
- A verifier MUST accept both forms: a bare bundle, and an envelope. When
  it sees an envelope it MUST verify `bundle` exactly as it would a bare
  one, and additionally check `body` against `post.sha256`.
- A verifier MUST NOT treat a missing body as a passed body check. It
  MUST distinguish "the text matches" from "no text was supplied", and
  say which to the reader, because those are different assurances.
- `body` is the published text as bytes, decoded as UTF-8.

The envelope is a convenience for demonstration and for readers who
receive a receipt on its own. A published receipt beside a published post
does not need it: the reader has the post.

## 4. Encodings

- Hashes are lowercase hexadecimal.
- The public key and signature are base64url without padding
  (RFC 4648 §5, no trailing `=`).
- All strings are UTF-8. The signing input is built from UTF-8 bytes.
- `ai_ranges[].from` and `.to` are UTF-8 **byte** offsets into the
  published body, half-open: `[from, to)`. Bytes, not characters and not
  UTF-16 code units, because a byte offset is the one position every
  language agrees on without a conversion table. A producer or verifier
  working in a language whose strings are not byte-indexed MUST convert.
  Getting this wrong is silent: the offsets still land somewhere, and
  they only diverge once the text contains a character outside ASCII.
- `timeline.checkpoints[].chars` counts Unicode **code points**, not
  bytes and not grapheme clusters. It is a size the author sees, so it
  counts characters; `ai_ranges` are positions a machine resolves, so
  they count bytes.

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

The two signatures share one key. The same Ed25519 key that
signs the outer bundle signs the embedded credential, so a verifier
that trusts the author's key trusts both at once, and a reader sees a
single fingerprint.

### 7.0 The credential object

A credential MUST have the shape below. A signature establishes that this
object was signed by the key it names; it does not establish that the
object is a content credential. Without a required shape, a signed pair
of fields carrying an asset hash and a signature satisfies every
cryptographic check, and a verifier that then calls it a valid content
credential has claimed more than it tested.

| Member | Type | Required | Rule |
| --- | --- | --- | --- |
| `@context` | string | yes | Exactly `https://c2pa.org/ns/manifest/1.4`. |
| `type` | string | yes | Exactly `ContentCredential`. |
| `asset` | object | yes | See below. |
| `claim_generator` | string | yes | Non-empty. Conventionally `Name/Version`. |
| `claim_generator_info` | object | yes | `name` is required and non-empty; `version` and `url` are optional strings. |
| `created_at` | string | yes | Canonical timestamp (section 4). |
| `assertions` | array | yes | MAY be empty. Each element is an object with a `label` string and a `data` value. |
| `signature` | object | yes | `alg`, `public_key`, `value`, as in section 3.1. |

`credential.asset`:

| Member | Type | Required | Rule |
| --- | --- | --- | --- |
| `sha256` | string | yes | 64 lowercase hex characters, and MUST equal `post.sha256`. |
| `size` | integer | yes | Non-negative: the published body's length in bytes. |
| `mime` | string | yes | Non-empty. |
| `title` | string | no | |
| `url` | string | no | |

Unlike the bundle, the credential MAY carry members this specification
does not define, at any depth. Its own signature is computed over the
whole object (section 7.1), so an unknown member there is signed rather
than smuggled. A verifier MUST preserve every member it does not
recognise when computing the digest: dropping one means hashing a
smaller object than the one that was signed, and two verifiers that drop
different members will disagree about a credential both should accept.

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
      `signature.public_key` (one key signs both). Where the
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
evidence and about the continuity of one embedded key. It is not a claim
about who holds that key: this format defines no mechanism binding a key
to a person, and a verifier that reports one is reporting something this
specification does not establish.

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
