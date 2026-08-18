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

	// Unknown members, preserved so the digest covers what was signed.
	extras map[string]json.RawMessage
}

// GeneratorInfo describes the tool chain that produced the manifest.
type GeneratorInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	URL     string `json:"url,omitempty"`

	// Unknown members, preserved so the digest covers what was signed.
	extras map[string]json.RawMessage
}

// Assertion is one labelled claim about the asset. Data is carried as
// raw JSON so a producer can extend the assertion set without this
// package modelling every label.
type Assertion struct {
	Label string          `json:"label"`
	Data  json.RawMessage `json:"data"`

	// Unknown members, preserved so the digest covers what was signed.
	extras map[string]json.RawMessage
}

// Signature is the Ed25519 envelope.
type Signature struct {
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"` // base64url, unpadded, raw 32-byte key
	Value     string `json:"value"`      // base64url, unpadded, raw 64-byte signature

	// Unknown members, preserved so the digest covers what was signed.
	extras map[string]json.RawMessage
}

// SignedManifest is a manifest plus its signature.
//
// The signature covers every member of the received object, including
// members this package does not model, so unknown members are preserved
// in `extras` and re-emitted. A credential from a newer implementation
// therefore still verifies here instead of failing because a field was
// dropped in transit.
//
// What is deliberately NOT done: keeping the original bytes and
// re-emitting those. That made a parsed credential two objects at once,
// the bytes it arrived as and the fields a caller could edit. Verifying
// checked the bytes while the binding checks in receipts/credential.go
// read the fields, so a parsed credential could be mutated and still
// verify, then marshal to something the verification never saw. One
// authoritative object, rebuilt from current fields plus extras, cannot
// drift from itself that way.
type SignedManifest struct {
	Manifest
	Signature Signature `json:"signature"`

	extras map[string]json.RawMessage
}

type signedManifestWire struct {
	Manifest
	Signature Signature `json:"signature"`
}

// modelledMembers are the top-level names signedManifestWire covers.
// Anything else in a received credential is an unknown member.
var modelledMembers = map[string]bool{
	"@context":             true,
	"type":                 true,
	"asset":                true,
	"claim_generator":      true,
	"claim_generator_info": true,
	"created_at":           true,
	"assertions":           true,
	"signature":            true,
}

// UnmarshalJSON decodes the modelled fields and keeps any others aside.
func (s *SignedManifest) UnmarshalJSON(b []byte) error {
	var w signedManifestWire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(b, &all); err != nil {
		return err
	}
	var extras map[string]json.RawMessage
	for name, raw := range all {
		if modelledMembers[name] {
			continue
		}
		if extras == nil {
			extras = make(map[string]json.RawMessage, 1)
		}
		extras[name] = raw
	}
	s.Manifest = w.Manifest
	s.Signature = w.Signature
	s.extras = extras
	return nil
}

// MarshalJSON encodes the current fields, then restores any unknown
// members. Member order does not matter: the digest is taken over the
// RFC 8785 canonical form, which sorts.
func (s SignedManifest) MarshalJSON() ([]byte, error) {
	base, err := json.Marshal(signedManifestWire{Manifest: s.Manifest, Signature: s.Signature})
	if err != nil {
		return nil, err
	}
	if len(s.extras) == 0 {
		return base, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(base, &obj); err != nil {
		return nil, err
	}
	for name, raw := range s.extras {
		if _, taken := obj[name]; taken {
			continue // a modelled field always wins over a stale extra
		}
		obj[name] = raw
	}
	return json.Marshal(obj)
}

// wireBytes returns the JSON form the signature is computed over.
func (s SignedManifest) wireBytes() ([]byte, error) {
	return s.MarshalJSON()
}
