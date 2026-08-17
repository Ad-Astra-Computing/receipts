# Receipts of Thought

The open trust core behind [Folio](https://github.com/Ad-Astra-Computing/folio),
a desktop writing app. When text is cheap to generate, the scarce resource
is a verifiable record of how it was created. This repository is that
record's format and the code that checks it.

It contains three things:

- [`SPEC.md`](SPEC.md): the receipts bundle format and Ed25519 signing scheme.
- A Go module (`receipts/`, `c2pa/`, `provenance/`, `history/`, `claims/`)
  that builds, signs and verifies bundles. Standard library only.
- [`verifier/`](verifier/): the client-side verifier that runs at
  [receiptsofthought.com](https://receiptsofthought.com).

A receipts bundle is one signed JSON file (`.receipts.json`) that travels
with a published piece of writing. It lets a reader check that the text,
the disclosed writing record, the credential and the author's signature
still agree.

## What is in a receipt

- A reference to the published text: title, URL and SHA-256 hash.
- A signed, C2PA-aligned content credential.
- The AI-authored character ranges the author chose to disclose.
- Sourced claims, each an excerpt and a source URL.
- A privacy-preserving digest of the composition timeline: per-checkpoint
  word and character counts plus a tamper-evident hash chain, never the
  draft text.

All of it is signed as one unit with a single Ed25519 key. The format
version is `folio.receipts/1`. Breaking changes carry a new schema
string, and verifiers reject schemas they do not recognise.

The wire format is versioned by that schema constant. The Go module is
at v0.x and makes no API stability promise.

## Verify a receipt

Open [receiptsofthought.com](https://receiptsofthought.com) and drop a
`.receipts.json` file onto the page. Verification runs entirely in your
browser with WebCrypto. Once the page has loaded, it consults no server.

It checks:

- the bundle's Ed25519 signature,
- the embedded content credential's own signature and its bindings to the
  bundle around it,
- the composition timeline's hash chain,
- that the published text matches the hash recorded in the bundle.

## Use the Go module

```sh
go get github.com/Ad-Astra-Computing/receipts
```

The module is pure format and crypto: it reads no files, opens no
network connections and never loads, stores or generates a key. A
producer holds its own storage and its own Ed25519 key, assembles the
wire types and signs.

```go
import (
    "time"

    "github.com/Ad-Astra-Computing/receipts/c2pa"
    "github.com/Ad-Astra-Computing/receipts/history"
    "github.com/Ad-Astra-Computing/receipts/receipts"
)

manifest, err := c2pa.Build(c2pa.BuildInput{Asset: asset, Generator: gen})
cred, err := c2pa.Sign(manifest, key)

bundle := receipts.Bundle{
    Schema:     receipts.Schema,
    Generated:  time.Now(), // Sign truncates this to whole UTC seconds
    Post:       receipts.PostRef{Title: title, URL: url, SHA256: bodyHash},
    Credential: cred,
    // history.DigestTimeline takes composition snapshots and returns the
    // digest. receipts.DigestTimeline takes checkpoints that are already
    // digested, and only chains them.
    Timeline: history.DigestTimeline(snapshots),
}
signed, err := receipts.Sign(bundle, key)

err = receipts.VerifyBody(signed, body)
```

The packages:

| Package | Holds |
| --- | --- |
| `receipts` | the bundle wire types, the signing digest, the timeline chain, `Sign`, `Verify`, `VerifyBody` |
| `c2pa` | the content credential types, `Build`, `Sign`, `Verify` and the RFC 8785 canonicalizer the credential signature uses |
| `provenance` | the AI-disclosure event type, its hash chain and `VerifyChain` |
| `history` | the composition snapshot and `DigestTimeline` |
| `claims` | the sourced-claim wire types, validation and a canonical digest |

`go test ./...` signs a bundle in Go and runs the TypeScript verifier's
suite against it, so the two implementations cannot drift apart
unnoticed. It needs the verifier's dependencies installed and skips
itself when they are not.

## What a valid receipt proves

A valid bundle proves that the recorded process, the credential and the
published body have not changed since the named key signed them, and that
they agree with one another.

It does not prove that a human, rather than a pipeline, wrote the piece.
No signing tool can prove intent. The honest claim is tamper evidence
plus one author identity, checkable by anyone, trusting no server.
Section 9 of [`SPEC.md`](SPEC.md) states this in full.

## Why the code is here

The verifier trusts neither a server nor its own operator. You still
trust whoever served the page to have delivered the code faithfully,
which is exactly why the code is public: read it, and host it yourself if
you prefer. The verifier implements the signing digest and timeline chain
from the specification, and its tests run a signed fixture through the
browser code, including rejection of a tampered body and a reordered
timeline, so a change that breaks the format fails a test.

## Run the verifier locally

```sh
cd verifier
npm install
npm test          # verify a signed fixture through the browser code
npm run dev       # local page; drop a .receipts.json bundle onto it
npm run build     # static output in dist/
```

With Nix, and without installing a toolchain at all:

```sh
nix build github:Ad-Astra-Computing/receipts#verifier
```

leaves the built site in `result/`, ready to serve from any static host.
`nix flake check` runs the Go suite and the gofmt gate, and `nix develop`
gives you both toolchains.

## Relationship to C2PA

A receipts bundle carries a C2PA-aligned content credential and adds the
composition-process assertions C2PA does not model. It follows C2PA's
data model and departs from its serialization and trust model: the
assertion store is JSON rather than CBOR; the signature is raw Ed25519
over RFC 8785 canonical JSON rather than COSE_Sign1; and trust is
anchored in the author's own public key rather than an X.509 chain
against a C2PA trust list. It is not a full C2PA manifest and a general
C2PA implementation does not read it. Section 7 of the specification
sets out every difference.

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

The trust core is permissively licensed on purpose. Independent verifiers
and platforms that embed receipt checking make the format more useful and
harder to fake. The Folio editor is licensed separately under AGPL-3.0.
The hosted Folio services are not open source.

Built and maintained by [Ad Astra Computing](https://adastracomputing.com).
