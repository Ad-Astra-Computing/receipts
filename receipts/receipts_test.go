// SPDX-License-Identifier: Apache-2.0

package receipts_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Ad-Astra-Computing/receipts/c2pa"
	"github.com/Ad-Astra-Computing/receipts/receipts"
)

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv
}

// buildBundle assembles a bundle the way a producer would: hash the
// body, sign a credential over it, digest the timeline, then sign.
func buildBundle(t *testing.T, key ed25519.PrivateKey, body string) receipts.Bundle {
	t.Helper()
	sum := sha256.Sum256([]byte(body))
	assetHash := hex.EncodeToString(sum[:])

	manifest, err := c2pa.Build(c2pa.BuildInput{
		Asset: c2pa.Asset{
			SHA256: assetHash,
			Size:   int64(len(body)),
			MIME:   "text/markdown",
			Title:  c2pa.Optional("Keep the receipts"),
			URL:    c2pa.Optional("https://blog.example.com/post/keep-the-receipts/"),
		},
		Generator: c2pa.GeneratorInfo{Name: "Folio", Version: c2pa.Optional("0.1.0")},
		CreatedAt: time.Date(2026, 7, 20, 14, 50, 51, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("c2pa build: %v", err)
	}
	cred, err := c2pa.Sign(manifest, key)
	if err != nil {
		t.Fatalf("c2pa sign: %v", err)
	}

	timeline := receipts.DigestTimeline([]receipts.Checkpoint{
		{At: time.Date(2026, 7, 20, 13, 0, 0, 0, time.UTC), Words: 40, Chars: 210, Hash: strings.Repeat("a", 64)},
		{At: time.Date(2026, 7, 20, 13, 20, 0, 0, time.UTC), Words: 90, Chars: 480, Hash: strings.Repeat("b", 64)},
	})

	b := receipts.Bundle{
		Schema:     receipts.Schema,
		Generated:  time.Date(2026, 7, 20, 14, 50, 51, 0, time.UTC),
		Post:       receipts.PostRef{Title: "Keep the receipts", URL: "https://blog.example.com/post/keep-the-receipts/", SHA256: assetHash},
		Credential: cred,
		AIRanges:   []receipts.AIRange{{From: 10, To: 28, Model: "claude-opus-4-8", When: "2026-07-20T14:50:00Z"}},
		Claims:     []receipts.ClaimRef{{Excerpt: "an excerpt", SourceURL: "https://example.com/source", Status: "ok"}},
		Timeline:   timeline,
	}
	signed, err := receipts.Sign(b, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

const sampleBody = "When anyone can generate text, a clean draft proves nothing.\n"

func TestSignVerifyRoundTrip(t *testing.T) {
	key := testKey(t)
	b := buildBundle(t, key, sampleBody)
	if err := receipts.VerifyBody(b, []byte(sampleBody)); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifySurvivesJSONRoundTrip(t *testing.T) {
	key := testKey(t)
	b := buildBundle(t, key, sampleBody)
	wire, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var parsed receipts.Bundle
	if err := json.Unmarshal(wire, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := receipts.VerifyBody(parsed, []byte(sampleBody)); err != nil {
		t.Fatalf("verify after round trip: %v", err)
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	key := testKey(t)
	cases := map[string]func(b *receipts.Bundle){
		"schema":    func(b *receipts.Bundle) { b.Schema = "folio.receipts/2" },
		"alg":       func(b *receipts.Bundle) { b.Signature.Alg = "RSA" },
		"title":     func(b *receipts.Bundle) { b.Post.Title = "A Different Title" },
		"url":       func(b *receipts.Bundle) { b.Post.URL = "https://evil.example.com/" },
		"ai range":  func(b *receipts.Bundle) { b.AIRanges[0].To = 999 },
		"claim":     func(b *receipts.Bundle) { b.Claims[0].SourceURL = "https://evil.example.com/" },
		"generated": func(b *receipts.Bundle) { b.Generated = b.Generated.Add(time.Hour) },
		"chain":     func(b *receipts.Bundle) { b.Timeline.ChainHash = "00" },
		"checkpoint": func(b *receipts.Bundle) {
			b.Timeline.Checkpoints[0].Words = 41
		},
		"public key": func(b *receipts.Bundle) { b.Signature.PublicKey = "short" },
		"value":      func(b *receipts.Bundle) { b.Signature.Value = "short" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b := buildBundle(t, key, sampleBody)
			mutate(&b)
			if err := receipts.Verify(b); err == nil {
				t.Fatalf("expected a tampered %s to be rejected", name)
			}
		})
	}
}

func TestVerifyRejectsForeignCredential(t *testing.T) {
	key := testKey(t)
	other := testKey(t)
	b := buildBundle(t, key, sampleBody)
	foreign := buildBundle(t, other, sampleBody)

	// A credential signed by a different key, valid in itself, must not
	// be accepted inside this bundle: one key signs both. Sign now
	// refuses to produce it at all, which is the earlier and better
	// failure, and Verify still refuses a bundle assembled by hand.
	b.Credential = foreign.Credential
	if _, err := receipts.Sign(b, key); err == nil {
		t.Fatal("signed a bundle whose credential belongs to another key")
	}
	if err := receipts.Verify(b); err == nil {
		t.Fatal("expected a credential signed by another key to be rejected")
	}
}

func TestVerifyRejectsCredentialBoundToAnotherBody(t *testing.T) {
	key := testKey(t)
	b := buildBundle(t, key, sampleBody)
	other := buildBundle(t, key, "a different body entirely\n")
	b.Credential = other.Credential
	if _, err := receipts.Sign(b, key); err == nil {
		t.Fatal("signed a bundle whose credential describes another body")
	}
	if err := receipts.Verify(b); err == nil {
		t.Fatal("expected a credential bound to another body to be rejected")
	}
}

func TestVerifyBodyRejectsWrongBody(t *testing.T) {
	key := testKey(t)
	b := buildBundle(t, key, sampleBody)
	if err := receipts.VerifyBody(b, []byte(sampleBody+" tampered")); err == nil {
		t.Fatal("expected a body mismatch to be rejected")
	}
}

func TestSignRejectsBadKey(t *testing.T) {
	if _, err := receipts.Sign(receipts.Bundle{}, ed25519.PrivateKey("too short")); err == nil {
		t.Fatal("expected an invalid key to be rejected")
	}
}

func TestDigestTimelineChainsEveryField(t *testing.T) {
	at := time.Date(2026, 7, 20, 13, 0, 0, 0, time.UTC)
	base := []receipts.Checkpoint{
		{At: at, Words: 40, Chars: 210, Hash: strings.Repeat("a", 64)},
		{At: at.Add(time.Minute), Words: 90, Chars: 480, Hash: strings.Repeat("b", 64)},
	}
	d := receipts.DigestTimeline(base)
	if !receipts.VerifyTimeline(d) {
		t.Fatal("freshly digested timeline does not verify")
	}
	for i, mutate := range []func(cps []receipts.Checkpoint){
		func(cps []receipts.Checkpoint) { cps[0].Words++ },
		func(cps []receipts.Checkpoint) { cps[0].Chars++ },
		func(cps []receipts.Checkpoint) { cps[0].Hash = "cc" },
		func(cps []receipts.Checkpoint) { cps[0].At = cps[0].At.Add(time.Second) },
		func(cps []receipts.Checkpoint) { cps[0], cps[1] = cps[1], cps[0] },
	} {
		cps := append([]receipts.Checkpoint(nil), base...)
		mutate(cps)
		altered := receipts.DigestTimeline(cps)
		if altered.ChainHash == d.ChainHash {
			t.Fatalf("mutation %d did not change the chain hash", i)
		}
	}

	// Sub-second precision is normalized away, so the chain is
	// reproducible from the rendered RFC 3339 timestamps alone.
	fuzzed := append([]receipts.Checkpoint(nil), base...)
	fuzzed[0].At = fuzzed[0].At.Add(400 * time.Millisecond)
	if receipts.DigestTimeline(fuzzed).ChainHash != d.ChainHash {
		t.Fatal("sub-second precision leaked into the chain")
	}

	if got := receipts.DigestTimeline(nil); got.ChainHash != "" {
		t.Fatalf("empty timeline chain hash = %q, want empty", got.ChainHash)
	}
}

// A disclosed range is a claim about specific characters of the
// published text. Once the text is in hand, a range that runs past its
// end, or that starts inside a character, describes nothing the reader
// can see, and must not verify.
func TestVerifyBody_rejectsRangesThatDoNotFitTheBody(t *testing.T) {
	key := testKey(t)
	const body = "héllo world, this is the published text"
	withRanges := func(rs []receipts.AIRange) receipts.Bundle {
		b := buildBundle(t, key, body)
		b.AIRanges = rs
		signed, err := receipts.Sign(b, key)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return signed
	}

	// Past the end.
	if err := receipts.VerifyBody(withRanges([]receipts.AIRange{{From: 0, To: len(body) + 5}}), []byte(body)); err == nil {
		t.Error("accepted a range ending past the end of the body")
	}
	// Starting inside the two-byte é.
	if err := receipts.VerifyBody(withRanges([]receipts.AIRange{{From: 2, To: 6}}), []byte(body)); err == nil {
		t.Error("accepted a range starting inside a character")
	}
	// A range that does fit, on character boundaries, still verifies.
	if err := receipts.VerifyBody(withRanges([]receipts.AIRange{{From: 0, To: 6}}), []byte(body)); err != nil {
		t.Errorf("rejected a range that fits the body: %v", err)
	}
}

// Sign verifies what it just built, but validation only looked at values
// a decoder had produced. A producer could hand in a timestamp with
// sub-second precision or a string with invalid UTF-8, watch it sign,
// and ship something that fails as soon as anyone parses it back.
func TestSignRefusesValuesTheWireCannotCarry(t *testing.T) {
	key := testKey(t)

	// Sign truncates `generated` itself, which is a documented
	// normalization rather than a refusal, so the check is that the
	// artifact it produces is one the wire form can carry.
	t.Run("sub-second generated is truncated, not signed as-is", func(t *testing.T) {
		b := buildBundle(t, key, sampleBody)
		b.Generated = b.Generated.Add(500 * time.Millisecond)
		signed, err := receipts.Sign(b, key)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if signed.Generated.Nanosecond() != 0 {
			t.Fatal("signed a timestamp the wire form cannot express")
		}
		wire, err := json.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		var back receipts.Bundle
		if err := json.Unmarshal(wire, &back); err != nil {
			t.Fatalf("the bundle it signed does not parse back: %v", err)
		}
		if err := receipts.Verify(back); err != nil {
			t.Fatalf("the bundle it signed does not verify after a round trip: %v", err)
		}
	})

	t.Run("non-canonical ai range when", func(t *testing.T) {
		b := buildBundle(t, key, sampleBody)
		b.AIRanges = []receipts.AIRange{{From: 0, To: 4, When: "2026-01-01T05:00:00+05:00"}}
		if _, err := receipts.Sign(b, key); err == nil {
			t.Fatal("signed a timestamp with a zone offset")
		}
	})

	t.Run("invalid UTF-8 in the title", func(t *testing.T) {
		b := buildBundle(t, key, sampleBody)
		b.Post.Title = string([]byte{0x48, 0xff, 0x69})
		if _, err := receipts.Sign(b, key); err == nil {
			t.Fatal("signed a title that is not valid UTF-8")
		}
	})
}
