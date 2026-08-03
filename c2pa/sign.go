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
	return signed, nil
}

// Verify recomputes the credential digest and checks the signature
// against the embedded public key, and rejects a `created_at` that is
// not whole-second UTC (SPEC.md section 3). Malformed input is an
// error, never a panic, so a verifier can reject a credential rather
// than abort.
func Verify(s SignedManifest) error {
	if s.Signature.Alg != "Ed25519" {
		return fmt.Errorf("c2pa: unsupported alg %q", s.Signature.Alg)
	}
	if s.CreatedAt.Nanosecond() != 0 || s.CreatedAt.Location() != time.UTC {
		return errors.New("c2pa: created_at is not a whole-second UTC timestamp")
	}
	pub, err := base64.RawURLEncoding.DecodeString(s.Signature.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("c2pa: bad public key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(s.Signature.Value)
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
