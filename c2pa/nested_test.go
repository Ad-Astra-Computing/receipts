// SPDX-License-Identifier: Apache-2.0

package c2pa

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// The credential's signature covers every member of the object,
// including ones this package does not model. Top-level unknowns are
// preserved. Nested ones were not: a member inside asset, generator info,
// an assertion or the signature was dropped at parse, so the digest was
// taken over a smaller object than the one that was signed. The browser
// canonicalizes exactly what it parsed, so it and Go hashed different
// bytes for the same credential.
func TestNestedUnknownCredentialMembersSurvive(t *testing.T) {
	signed, key := testManifest(t)
	wire, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(wire, &obj); err != nil {
		t.Fatal(err)
	}
	obj["asset"].(map[string]any)["future_asset_field"] = "kept"
	obj["claim_generator_info"].(map[string]any)["future_gen_field"] = "kept"
	obj["signature"].(map[string]any)["future_sig_field"] = "kept"
	withNested, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}

	var parsed SignedManifest
	if err := json.Unmarshal(withNested, &parsed); err != nil {
		t.Fatal(err)
	}
	digest, err := Digest(parsed)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Signature.Value = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, digest))

	out, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"future_asset_field", "future_gen_field", "future_sig_field"} {
		if !strings.Contains(string(out), name) {
			t.Errorf("%s was dropped, so the digest covered less than was signed", name)
		}
	}
	var back SignedManifest
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if err := Verify(back); err != nil {
		t.Fatalf("a credential with nested unknown members should verify: %v", err)
	}
}
