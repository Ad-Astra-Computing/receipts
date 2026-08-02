// SPDX-License-Identifier: Apache-2.0

package receipts

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Sign fills in b.Signature with an Ed25519 signature over the signing
// digest and returns the signed bundle. The key stays the caller's:
// this package never loads, stores or generates one.
func Sign(b Bundle, key ed25519.PrivateKey) (Bundle, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Bundle{}, errors.New("receipts: invalid signing key")
	}
	pub := key.Public().(ed25519.PublicKey)
	b.Signature = Signature{
		Alg:       "Ed25519",
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
	}
	digest, err := SigningDigest(b)
	if err != nil {
		return Bundle{}, err
	}
	b.Signature.Value = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, digest))
	return b, nil
}

// SigningDigest is the interop-clean signing input from SPEC.md
// section 6: a SHA-256 over the concatenated per-field SHA-256 hashes,
// in a fixed order. Because every field is hashed to a fixed 32 bytes
// before concatenation there is no delimiter-injection risk and no JSON
// canonicalization ambiguity, so a browser reproduces it with only
// SHA-256 and UTF-8 encoding. The signature covers the embedded C2PA
// credential through its signature value and the whole timeline through
// its chain hash, so those structures are bound without re-listing
// every field.
func SigningDigest(b Bundle) ([]byte, error) {
	h := sha256.New()
	add := func(s string) {
		x := sha256.Sum256([]byte(s))
		h.Write(x[:])
	}
	add(SigTag)
	add(b.Schema)
	add(b.Generated.UTC().Format(time.RFC3339))
	add(b.Post.Title)
	add(b.Post.URL)
	add(b.Post.SHA256)
	add(b.Credential.Signature.Value)
	add(b.Timeline.ChainHash)
	add(strconv.Itoa(len(b.AIRanges)))
	for _, r := range b.AIRanges {
		add(strconv.Itoa(r.From) + "," + strconv.Itoa(r.To))
		add(r.Model)
		add(r.When)
	}
	add(strconv.Itoa(len(b.Claims)))
	for _, c := range b.Claims {
		add(c.Excerpt)
		add(c.SourceURL)
		add(c.Status)
	}
	return h.Sum(nil), nil
}

// Verify checks that a bundle is internally consistent and correctly
// signed: the outer signature, the embedded C2PA credential and its
// bindings, and the timeline chain. It does not check the body hash
// against a body; callers holding the body use VerifyBody.
func Verify(b Bundle) error {
	if b.Schema != Schema {
		return fmt.Errorf("receipts: unknown schema %q", b.Schema)
	}
	if b.Signature.Alg != "Ed25519" {
		return fmt.Errorf("receipts: unsupported alg %q", b.Signature.Alg)
	}
	pub, err := base64.RawURLEncoding.DecodeString(b.Signature.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("receipts: bad public key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(b.Signature.Value)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("receipts: bad signature value")
	}
	digest, err := SigningDigest(b)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, digest, sig) {
		return errors.New("receipts: signature does not match bundle")
	}
	if err := c2paVerify(b); err != nil {
		return err
	}
	if !VerifyTimeline(b.Timeline) {
		return errors.New("receipts: timeline chain hash mismatch")
	}
	return nil
}

// VerifyBody additionally confirms the bundle describes the given
// published body.
func VerifyBody(b Bundle, body []byte) error {
	if err := Verify(b); err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != b.Post.SHA256 {
		return errors.New("receipts: body does not match bundle hash")
	}
	return nil
}
