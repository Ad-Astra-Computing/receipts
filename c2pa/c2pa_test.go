// SPDX-License-Identifier: Apache-2.0

package c2pa

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv
}

func sampleInput() BuildInput {
	return BuildInput{
		Asset: Asset{
			SHA256: strings.Repeat("a", 64),
			Size:   299,
			MIME:   "text/markdown",
			Title:  "Keep the receipts",
			URL:    "https://blog.example.com/post/keep-the-receipts/",
		},
		Generator: GeneratorInfo{Name: "Folio", Version: "0.1.0", URL: "https://example.com"},
		CreatedAt: time.Date(2026, 7, 20, 14, 50, 51, 123456789, time.UTC),
		AIRanges: []AIRange{{
			From: 10, To: 28, Model: "claude-opus-4-8",
			EventID: "abc123", Hash: strings.Repeat("b", 64),
			When: "2026-07-20T14:50:00Z",
		}},
		ChainLen: 1,
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	a, err := Build(sampleInput())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	b, err := Build(sampleInput())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Fatalf("build is not deterministic:\n%s\n%s", ja, jb)
	}
	if !a.CreatedAt.Equal(time.Date(2026, 7, 20, 14, 50, 51, 0, time.UTC)) {
		t.Fatalf("created_at not truncated to whole seconds: %s", a.CreatedAt)
	}
}

func TestBuildAssertions(t *testing.T) {
	m, err := Build(sampleInput())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	labels := make([]string, 0, len(m.Assertions))
	for _, a := range m.Assertions {
		labels = append(labels, a.Label)
	}
	want := []string{"c2pa.training-mining", "folio.ai_ranges", "c2pa.actions"}
	if len(labels) != len(want) {
		t.Fatalf("assertions %v, want %v", labels, want)
	}
	for i := range want {
		if labels[i] != want[i] {
			t.Fatalf("assertions %v, want %v", labels, want)
		}
	}

	in := sampleInput()
	in.AIRanges = nil
	m, err = Build(in)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, a := range m.Assertions {
		if a.Label == "folio.ai_ranges" {
			t.Fatal("empty AI ranges must not emit a folio.ai_ranges assertion")
		}
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	key := testKey(t)
	m, err := Build(sampleInput())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	signed, err := Sign(m, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Verify(signed); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if signed.Signature.Alg != "Ed25519" || signed.Signature.Value == "" {
		t.Fatalf("signature envelope not filled: %+v", signed.Signature)
	}

	again, err := Sign(m, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if again.Signature.Value != signed.Signature.Value {
		t.Fatal("signing the same manifest twice produced different bytes")
	}
}

func TestVerifySurvivesJSONRoundTrip(t *testing.T) {
	key := testKey(t)
	m, _ := Build(sampleInput())
	signed, err := Sign(m, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	wire, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var parsed SignedManifest
	if err := json.Unmarshal(wire, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := Verify(parsed); err != nil {
		t.Fatalf("verify after round trip: %v", err)
	}
	again, err := json.Marshal(parsed)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(again) != string(wire) {
		t.Fatalf("re-marshal changed the bytes:\n%s\n%s", wire, again)
	}
}

func TestVerifyCoversUnmodelledFields(t *testing.T) {
	key := testKey(t)
	m, _ := Build(sampleInput())
	signed, _ := Sign(m, key)
	wire, _ := json.Marshal(signed)

	// A field this package does not model must still be covered: adding
	// one after signing has to fail verification.
	withExtra := strings.Replace(string(wire), `{"@context"`, `{"future_field":"x","@context"`, 1)
	var parsed SignedManifest
	if err := json.Unmarshal([]byte(withExtra), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := Verify(parsed); err == nil {
		t.Fatal("expected an injected field to break the credential signature")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	key := testKey(t)
	m, _ := Build(sampleInput())
	signed, _ := Sign(m, key)

	cases := map[string]func(s *SignedManifest){
		"alg":        func(s *SignedManifest) { s.Signature.Alg = "RSA" },
		"public key": func(s *SignedManifest) { s.Signature.PublicKey = "short" },
		"value":      func(s *SignedManifest) { s.Signature.Value = "short" },
		"asset hash": func(s *SignedManifest) { s.Asset.SHA256 = strings.Repeat("d", 64) },
		"generator":  func(s *SignedManifest) { s.ClaimGenerator = "Impostor/9.9.9" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			bad := signed
			mutate(&bad)
			if err := Verify(bad); err == nil {
				t.Fatalf("expected a tampered %s to be rejected", name)
			}
		})
	}
}

func TestSignRejectsBadKey(t *testing.T) {
	if _, err := Sign(Manifest{}, ed25519.PrivateKey("too short")); err == nil {
		t.Fatal("expected an invalid key to be rejected")
	}
}
