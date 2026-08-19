// SPDX-License-Identifier: Apache-2.0

package c2pa

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// Digest computes the credential signing digest from SPEC.md section
// 7.1: SHA-256 over the domain tag followed by the RFC 8785 canonical
// JSON of the credential with only signature.value removed.
// signature.alg and signature.public_key stay inside the signed
// payload, so neither the declared algorithm nor the author key can be
// swapped after signing.
func Digest(s SignedManifest) ([]byte, error) {
	wire, err := s.wireBytes()
	if err != nil {
		return nil, err
	}
	obj, err := decodeJSON(wire)
	if err != nil {
		return nil, err
	}
	if sig, ok := obj["signature"].(map[string]any); ok {
		delete(sig, "value")
	}
	canonical, err := canonicalValue(obj)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(CredSigTag + canonical))
	return sum[:], nil
}

// Sign signs m with key and returns the signed credential. The same
// (manifest, key) pair always yields the same signature bytes.
//
// Sign normalizes m.CreatedAt to whole UTC seconds, as SPEC.md section
// 3 requires of every timestamp in a bundle. Build already does this,
// but a producer may assemble a Manifest by hand, and a credential is
// not conforming if its wire timestamp carries sub-second precision or
// a zone offset other than Z.
// Sign refuses to produce a credential its own Verify would reject.
// Emitting one is worse than failing: the producer learns nothing until
// a reader tries to check the receipt, and by then it is published.
func Sign(m Manifest, key ed25519.PrivateKey) (SignedManifest, error) {
	if len(key) != ed25519.PrivateKeySize {
		return SignedManifest{}, errors.New("c2pa: invalid signing key")
	}
	m.CreatedAt = m.CreatedAt.UTC().Truncate(time.Second)
	pub := key.Public().(ed25519.PublicKey)
	signed := SignedManifest{
		Manifest: m,
		Signature: Signature{
			Alg:       "Ed25519",
			PublicKey: base64.RawURLEncoding.EncodeToString(pub),
		},
	}
	digest, err := Digest(signed)
	if err != nil {
		return SignedManifest{}, err
	}
	signed.Signature.Value = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, digest))
	if err := Verify(signed); err != nil {
		return SignedManifest{}, fmt.Errorf("c2pa: refusing to sign a credential that would not verify: %w", err)
	}
	return signed, nil
}

// Verify recomputes the credential digest and checks the signature
// against the embedded public key, and rejects a `created_at` that is
// not whole-second UTC (SPEC.md section 3). Malformed input is an
// error, never a panic, so a verifier can reject a credential rather
// than abort.
// ValidateShape checks that a credential is the object SPEC section 7
// describes, before any cryptography is attempted.
//
// A signature proves that whatever is in front of you was signed by the
// named key. It says nothing about whether that object is a content
// credential. Without this, a signed `{"asset":{"sha256":...},
// "signature":...}` verifies and gets presented to a reader as a valid
// content credential, which is a stronger thing than what was checked.
func ValidateShape(s SignedManifest) error {
	if s.Context != ContextURI {
		return fmt.Errorf("c2pa: @context is %q, want %q", s.Context, ContextURI)
	}
	if s.Type != ManifestType {
		return fmt.Errorf("c2pa: type is %q, want %q", s.Type, ManifestType)
	}
	if !isSHA256Hex(s.Asset.SHA256) {
		return fmt.Errorf("c2pa: asset.sha256 is not 64 lowercase hex characters")
	}
	if s.Asset.Size < 0 {
		return fmt.Errorf("c2pa: asset.size is negative")
	}
	if s.Asset.MIME == "" {
		return errors.New("c2pa: asset.mime is empty")
	}
	if s.ClaimGenerator == "" {
		return errors.New("c2pa: claim_generator is empty")
	}
	if s.GeneratorInfo.Name == "" {
		return errors.New("c2pa: claim_generator_info.name is empty")
	}
	if s.CreatedAt.IsZero() {
		return errors.New("c2pa: created_at is missing")
	}
	if s.Assertions == nil {
		return errors.New("c2pa: assertions is missing")
	}
	for i, a := range s.Assertions {
		if a.Label == "" {
			return fmt.Errorf("c2pa: assertions[%d].label is empty", i)
		}
		// Required by SPEC 7.0. A null payload is a value and is kept;
		// no payload at all is not.
		if len(a.Data) == 0 {
			return fmt.Errorf("c2pa: assertions[%d] has no data", i)
		}
	}
	return nil
}

// isSHA256Hex reports whether h is exactly 64 lowercase hex digits.
// Case matters: SPEC section 4 fixes lowercase, and a verifier that
// accepted either would compare hashes that a stricter one would not.
func isSHA256Hex(h string) bool {
	if len(h) != 64 {
		return false
	}
	for _, c := range h {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func Verify(s SignedManifest) error {
	if err := ValidateShape(s); err != nil {
		return err
	}
	if s.Signature.Alg != "Ed25519" {
		return fmt.Errorf("c2pa: unsupported alg %q", s.Signature.Alg)
	}
	if s.CreatedAt.Nanosecond() != 0 || s.CreatedAt.Location() != time.UTC {
		return errors.New("c2pa: created_at is not a whole-second UTC timestamp")
	}
	pub, err := base64.RawURLEncoding.Strict().DecodeString(s.Signature.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("c2pa: bad public key")
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(s.Signature.Value)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("c2pa: bad signature value")
	}
	digest, err := Digest(s)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, digest, sig) {
		return errors.New("c2pa: signature does not match manifest")
	}
	return nil
}
