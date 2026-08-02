// SPDX-License-Identifier: Apache-2.0

// Package c2pa builds, signs and verifies the content credential that
// travels inside a receipts bundle.
//
// The credential is a C2PA-aligned JSON manifest: it binds the SHA-256
// of the published body, the tool that produced it, and a set of
// labelled assertions, to one Ed25519 author key. Signing follows
// SPEC.md section 7.1: Ed25519 over
//
//	SHA-256( UTF8("folio.c2pa.sig.v1") || UTF8( JCS(credential without signature.value) ) )
//
// where JCS is RFC 8785 canonical JSON, implemented here and in
// verifier/src/jcs.ts so a producer in either language verifies in the
// other.
//
// GAP FROM FULL C2PA. The full standard wraps the assertion store in
// CBOR and signs with COSE_Sign1 over an X.509 trust list. This
// manifest uses JSON and raw Ed25519 because personal publishers have
// no CAs and a self-anchored public key fingerprint is verifiable
// today. The folio.* labels are the namespace for extensions; c2pa.*
// labels mirror the standard where the data is meaningful.
//
// The package is pure: it holds types and crypto, reads no files and
// never loads or stores a key.
package c2pa

import (
	"encoding/json"
	"time"
)

// CredSigTag is the domain separation tag mixed into the credential
// digest, distinct from the bundle tag so a credential signature can
// never be replayed as a bundle signature or the reverse.
const CredSigTag = "folio.c2pa.sig.v1"

// Manifest is the unsigned content credential body.
type Manifest struct {
	Context        string        `json:"@context"`
	Type           string        `json:"type"`
	Asset          Asset         `json:"asset"`
	ClaimGenerator string        `json:"claim_generator"`
	GeneratorInfo  GeneratorInfo `json:"claim_generator_info"`
	CreatedAt      time.Time     `json:"created_at"`
	Assertions     []Assertion   `json:"assertions"`
}

// Asset identifies the published body the manifest is about.
type Asset struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	MIME   string `json:"mime"`
	Title  string `json:"title,omitempty"`
	URL    string `json:"url,omitempty"`
}

// GeneratorInfo describes the tool chain that produced the manifest.
type GeneratorInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	URL     string `json:"url,omitempty"`
}

// Assertion is one labelled claim about the asset. Data is carried as
// raw JSON so a producer can extend the assertion set without this
// package modelling every label.
type Assertion struct {
	Label string          `json:"label"`
	Data  json.RawMessage `json:"data"`
}

// Signature is the Ed25519 envelope.
type Signature struct {
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"` // base64url, unpadded, raw 32-byte key
	Value     string `json:"value"`      // base64url, unpadded, raw 64-byte signature
}

// SignedManifest is a manifest plus its signature.
//
// A SignedManifest parsed from JSON keeps the exact bytes it was parsed
// from and re-marshals to those bytes. Signature verification covers
// every member of the received object, including any this package does
// not model, so a credential produced by a newer implementation still
// verifies here rather than failing because a field was dropped on the
// way through.
type SignedManifest struct {
	Manifest
	Signature Signature `json:"signature"`

	raw json.RawMessage
}

type signedManifestWire struct {
	Manifest
	Signature Signature `json:"signature"`
}

// UnmarshalJSON decodes the modelled fields and retains the original
// bytes.
func (s *SignedManifest) UnmarshalJSON(b []byte) error {
	var w signedManifestWire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	s.Manifest = w.Manifest
	s.Signature = w.Signature
	s.raw = append(json.RawMessage(nil), b...)
	return nil
}

// MarshalJSON re-emits the bytes a parsed credential arrived as, and
// otherwise encodes the modelled fields.
func (s SignedManifest) MarshalJSON() ([]byte, error) {
	if len(s.raw) > 0 {
		return append([]byte(nil), s.raw...), nil
	}
	return json.Marshal(signedManifestWire{Manifest: s.Manifest, Signature: s.Signature})
}

// wireBytes returns the JSON form the signature is computed over.
func (s SignedManifest) wireBytes() ([]byte, error) {
	return s.MarshalJSON()
}
