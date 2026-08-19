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
	"unicode/utf8"
)

// Sign fills in b.Signature with an Ed25519 signature over the signing
// digest and returns the signed bundle. The key stays the caller's:
// this package never loads, stores or generates one.
//
// Sign normalizes b.Generated to whole UTC seconds before signing, as
// SPEC.md section 3 requires. The signing digest hashes the rendered
// RFC 3339 string, so a producer passing an un-truncated or non-UTC
// time would otherwise emit a bundle whose wire form differs from the
// string the signature covers: valid here, rejected by a verifier that
// hashes the wire string.
// Sign refuses to produce a bundle its own Verify would reject. A signer
// that can emit an artifact its verifier refuses is a trap: the producer
// hears nothing until a reader checks the receipt, by which point it is
// published.
func Sign(b Bundle, key ed25519.PrivateKey) (Bundle, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Bundle{}, errors.New("receipts: invalid signing key")
	}
	b.Generated = b.Generated.UTC().Truncate(time.Second)
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
	if err := Verify(b); err != nil {
		return Bundle{}, fmt.Errorf("receipts: refusing to sign a bundle that would not verify: %w", err)
	}
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

// wholeSecondUTC reports whether t renders as a whole-second UTC
// RFC 3339 timestamp, the only form SPEC.md section 3 allows. It reads
// the value a JSON decoder produced, so it catches both sub-second
// precision and a non-Z zone offset on the wire.
func wholeSecondUTC(t time.Time) bool {
	return t.Nanosecond() == 0 && t.Location() == time.UTC
}

// Verify checks that a bundle is internally consistent and correctly
// signed: the outer signature, the embedded C2PA credential and its
// bindings, and the timeline chain. It also rejects a `generated`
// timestamp that is not whole-second UTC, because the signing digest
// hashes the rendered timestamp and a verifier reading the wire string
// must arrive at the same bytes this one does. It does not check the
// body hash against a body; callers holding the body use VerifyBody.
func Verify(b Bundle) error {
	// A missing timeline is not an empty one. The chain of no checkpoints
	// is the empty string, so without this a bundle carrying no record of
	// composition verified here while the TypeScript verifier refused it.
	// A receipt whose whole subject is the composition record must have
	// one, even if it is empty.
	if b.Timeline.Checkpoints == nil {
		return errors.New("receipts: timeline.checkpoints is missing")
	}
	if err := validateSemantics(b); err != nil {
		return err
	}
	if b.Schema != Schema {
		return fmt.Errorf("receipts: unknown schema %q", b.Schema)
	}
	if b.Signature.Alg != "Ed25519" {
		return fmt.Errorf("receipts: unsupported alg %q", b.Signature.Alg)
	}
	if !wholeSecondUTC(b.Generated) {
		return errors.New("receipts: generated is not a whole-second UTC timestamp")
	}
	pub, err := base64.RawURLEncoding.Strict().DecodeString(b.Signature.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("receipts: bad public key")
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(b.Signature.Value)
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
	// Once the body is in hand, the disclosed ranges can be checked
	// against it. Without this a receipt could point past the end of the
	// text it describes, or into the middle of a character, and still
	// verify: the reader would be shown a disclosure that does not
	// correspond to anything they can read.
	for i, r := range b.AIRanges {
		if r.To > len(body) {
			return fmt.Errorf("receipts: ai_ranges[%d] ends past the end of the body", i)
		}
		if !utf8.RuneStart(body[r.From]) {
			return fmt.Errorf("receipts: ai_ranges[%d].from is inside a character, not at its start", i)
		}
		if r.To < len(body) && !utf8.RuneStart(body[r.To]) {
			return fmt.Errorf("receipts: ai_ranges[%d].to is inside a character, not at its start", i)
		}
	}
	return nil
}

// validateSemantics enforces the rules of SPEC sections 3.1 and 3.2 that
// are about values rather than shape.
//
// The TypeScript verifier checks these at parse; this side did not, so a
// bundle with a negative word count or an inverted AI range verified in
// Go and failed in the browser. A specification that states a rule which
// only one implementation applies is worse than one that stays silent,
// because an implementer reads it and believes it.
func validateSemantics(b Bundle) error {
	// In-memory values, which no decoder has seen. Sign calls Verify on
	// what it just built, so without these a producer could hand in a
	// timestamp with a zone offset or a string with invalid UTF-8, watch
	// it sign, and ship an artifact that fails the moment anyone parses
	// it back. Checking only what arrived over the wire made the signer's
	// guarantee true of received bundles and false of built ones.
	if _, err := canonicalTimestamp(b.Generated.UTC().Format(time.RFC3339)); err != nil {
		return fmt.Errorf("receipts: generated: %w", err)
	}
	if b.Generated.Nanosecond() != 0 {
		return errors.New("receipts: generated carries sub-second precision, which the wire form cannot express")
	}
	for i, cp := range b.Timeline.Checkpoints {
		if cp.At.Nanosecond() != 0 {
			return fmt.Errorf("receipts: timeline.checkpoints[%d].at carries sub-second precision", i)
		}
	}
	for i, r := range b.AIRanges {
		if r.When != "" {
			if _, err := canonicalTimestamp(r.When); err != nil {
				return fmt.Errorf("receipts: ai_ranges[%d].when: %w", i, err)
			}
		}
	}
	for _, str := range []struct {
		name  string
		value string
	}{
		{"post.title", b.Post.Title},
		{"post.url", b.Post.URL},
		{"post.sha256", b.Post.SHA256},
	} {
		if !utf8.ValidString(str.value) {
			return fmt.Errorf("receipts: %s is not valid UTF-8", str.name)
		}
	}
	for i, c := range b.Claims {
		if !utf8.ValidString(c.Excerpt) || !utf8.ValidString(c.SourceURL) {
			return fmt.Errorf("receipts: claims[%d] is not valid UTF-8", i)
		}
	}
	for i, cp := range b.Timeline.Checkpoints {
		if cp.Words < 0 {
			return fmt.Errorf("receipts: timeline.checkpoints[%d].words is negative", i)
		}
		if cp.Chars < 0 {
			return fmt.Errorf("receipts: timeline.checkpoints[%d].chars is negative", i)
		}
		if !isSHA256Hex(cp.Hash) {
			return fmt.Errorf("receipts: timeline.checkpoints[%d].hash is not 64 lowercase hex characters", i)
		}
	}
	for i, r := range b.AIRanges {
		if r.From < 0 {
			return fmt.Errorf("receipts: ai_ranges[%d].from is negative", i)
		}
		if r.To <= r.From {
			return fmt.Errorf("receipts: ai_ranges[%d] ends at or before it starts", i)
		}
	}
	for i, c := range b.Claims {
		if c.Excerpt == "" {
			return fmt.Errorf("receipts: claims[%d].excerpt is empty", i)
		}
		if c.SourceURL == "" {
			return fmt.Errorf("receipts: claims[%d].source_url is empty", i)
		}
	}
	// Counts are hashed into the chain and offsets index a body, so both
	// must survive a round trip through a JSON number in any language.
	// Go's int is wider than that; refusing here keeps a bundle Go signs
	// verifiable everywhere.
	for i, cp := range b.Timeline.Checkpoints {
		if !isSafeInteger(cp.Words) || !isSafeInteger(cp.Chars) {
			return fmt.Errorf("receipts: timeline.checkpoints[%d] has a count outside the safe integer range", i)
		}
	}
	for i, r := range b.AIRanges {
		if !isSafeInteger(r.From) || !isSafeInteger(r.To) {
			return fmt.Errorf("receipts: ai_ranges[%d] has an offset outside the safe integer range", i)
		}
	}
	return nil
}

// maxSafeInteger is 2^53-1: the largest integer every JSON
// implementation reproduces exactly (SPEC section 4).
const maxSafeInteger = 1<<53 - 1

func isSafeInteger(n int) bool { return n >= -maxSafeInteger && n <= maxSafeInteger }

// isSHA256Hex reports whether h is exactly 64 lowercase hex digits.
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
