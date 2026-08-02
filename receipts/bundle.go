// SPDX-License-Identifier: Apache-2.0

// Package receipts implements the receipts bundle: a portable, signed
// record of how a piece of writing was made, specified in SPEC.md.
//
// A bundle binds, and signs as a unit:
//
//   - a reference to the published body (title, canonical URL, sha256)
//   - a C2PA content credential, itself signed
//   - the disclosed AI-authored spans
//   - the sourced claims
//   - a DIGEST of the composition timeline
//
// Privacy is the load-bearing design choice: the timeline is a digest,
// per-checkpoint word and character counts plus a hash chain, never the
// draft text. It proves a process happened and is tamper-evident,
// without publishing drafts the author never chose to share.
//
// The package is pure. It holds the wire types, the signing digest,
// the timeline chain and verification. It reads no files, opens no
// network connections and knows nothing about the tool that produced
// the bundle. A producer assembles a Bundle from its own storage and
// calls Sign with an Ed25519 key it owns.
package receipts

import (
	"time"

	"github.com/Ad-Astra-Computing/receipts/c2pa"
)

// Schema identifies the bundle format.
const Schema = "folio.receipts/1"

// SigTag is the domain separation tag mixed into the signing digest,
// so a bundle signature can never be replayed as a signature over
// another Ed25519 payload.
const SigTag = "folio.receipts.sig.v1"

// PostRef points at the published body.
type PostRef struct {
	Title  string `json:"title,omitempty"`
	URL    string `json:"url,omitempty"`
	SHA256 string `json:"sha256"`
}

// AIRange is one disclosed AI-authored span.
type AIRange struct {
	From  int    `json:"from"`
	To    int    `json:"to"`
	Model string `json:"model,omitempty"`
	When  string `json:"when,omitempty"`
}

// ClaimRef is a sourced factual claim.
type ClaimRef struct {
	Excerpt   string `json:"excerpt"`
	SourceURL string `json:"source_url"`
	Status    string `json:"status,omitempty"`
}

// Checkpoint is one point on the composition timeline, digested: no
// draft text, only counts and the checkpoint's content hash.
type Checkpoint struct {
	At    time.Time `json:"at"`
	Words int       `json:"words"`
	Chars int       `json:"chars"`
	Hash  string    `json:"hash"`
}

// TimelineDigest is the privacy-preserving process record.
type TimelineDigest struct {
	Checkpoints []Checkpoint `json:"checkpoints"`
	// ChainHash chains every checkpoint field so a verifier can detect
	// any reordering, insertion or edit of the digest.
	ChainHash string `json:"chain_hash"`
}

// Signature is the Ed25519 envelope over the whole bundle.
type Signature struct {
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"`
	Value     string `json:"value"`
}

// Bundle is the complete, signed receipts artifact.
type Bundle struct {
	Schema     string              `json:"schema"`
	Generated  time.Time           `json:"generated"`
	Post       PostRef             `json:"post"`
	Credential c2pa.SignedManifest `json:"credential"`
	AIRanges   []AIRange           `json:"ai_ranges"`
	Claims     []ClaimRef          `json:"claims"`
	Timeline   TimelineDigest      `json:"timeline"`
	Signature  Signature           `json:"signature"`
}
