// SPDX-License-Identifier: Apache-2.0

package receipts_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
			Title:  "Keep the receipts",
			URL:    "https://blog.example.com/post/keep-the-receipts/",
		},
		Generator: c2pa.GeneratorInfo{Name: "Folio", Version: "0.1.0"},
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
		{At: time.Date(2026, 7, 20, 13, 0, 0, 0, time.UTC), Words: 40, Chars: 210, Hash: "aa"},
		{At: time.Date(2026, 7, 20, 13, 20, 0, 0, time.UTC), Words: 90, Chars: 480, Hash: "bb"},
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
	// be accepted inside this bundle: one author identity signs both.
	b.Credential = foreign.Credential
	b, err := receipts.Sign(b, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
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
	b, err := receipts.Sign(b, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
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
		{At: at, Words: 40, Chars: 210, Hash: "aa"},
		{At: at.Add(time.Minute), Words: 90, Chars: 480, Hash: "bb"},
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
