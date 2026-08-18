// SPDX-License-Identifier: Apache-2.0

package c2pa

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testManifest(t *testing.T) (SignedManifest, ed25519.PrivateKey) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Build(BuildInput{
		Asset:     Asset{SHA256: strings.Repeat("a", 64), Size: 10, MIME: "text/markdown"},
		Generator: GeneratorInfo{Name: "Test", Version: "1"},
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(m, key)
	if err != nil {
		t.Fatal(err)
	}
	return signed, key
}

// A parsed credential used to keep the bytes it arrived as and re-emit
// them, while the exported fields stayed writable. So a caller could
// change the asset hash, watch verification still pass because it
// checked the old bytes, and then marshal a credential whose content
// disagreed with what had just been verified. Verification must describe
// the object as it is now.
func TestParsedCredentialCannotBeMutatedBehindItsSignature(t *testing.T) {
	signed, _ := testManifest(t)
	wire, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	var parsed SignedManifest
	if err := json.Unmarshal(wire, &parsed); err != nil {
		t.Fatal(err)
	}
	if err := Verify(parsed); err != nil {
		t.Fatalf("a freshly parsed credential should verify: %v", err)
	}

	parsed.Asset.SHA256 = strings.Repeat("b", 64)
	if err := Verify(parsed); err == nil {
		t.Fatal("verified a credential whose asset hash had been changed after parsing")
	}
	out, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), strings.Repeat("b", 64)) {
		t.Fatal("marshaling re-emitted the original bytes instead of the current fields")
	}
}

// Unknown members are why the raw bytes were kept in the first place:
// the signature covers every member of the object, so a credential from
// a newer producer must survive a parse and re-marshal intact.
func TestUnknownCredentialMembersSurviveARoundTrip(t *testing.T) {
	signed, key := testManifest(t)
	wire, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(wire, &obj); err != nil {
		t.Fatal(err)
	}
	obj["future_field"] = map[string]any{"added_by": "a newer producer"}
	withExtra, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}

	// Re-sign so the signature covers the added member: parse it back,
	// then sign the digest of the object as it now stands.
	var resigned SignedManifest
	if err := json.Unmarshal(withExtra, &resigned); err != nil {
		t.Fatal(err)
	}
	digest, err := Digest(resigned)
	if err != nil {
		t.Fatal(err)
	}
	resigned.Signature.Value = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, digest))

	round, err := json.Marshal(resigned)
	if err != nil {
		t.Fatal(err)
	}
	var back SignedManifest
	if err := json.Unmarshal(round, &back); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(back)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "future_field") {
		t.Fatal("an unknown member was dropped on the way through")
	}
	if err := Verify(back); err != nil {
		t.Fatalf("a credential with an unknown member should still verify: %v", err)
	}
}
