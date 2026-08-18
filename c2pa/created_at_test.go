// SPDX-License-Identifier: Apache-2.0

package c2pa

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// SPEC.md section 3 requires whole-second UTC timestamps throughout the
// bundle, credential included. Build truncates, but a producer may
// assemble a Manifest by hand, so Sign must normalize too: otherwise
// the credential goes on the wire with a fractional or offset
// `created_at` that no longer matches the format.
func TestSignNormalizesCreatedAt(t *testing.T) {
	key := testKey(t)
	zone := time.FixedZone("CET", 2*60*60)
	for name, in := range map[string]time.Time{
		"fractional seconds": time.Date(2026, 7, 20, 14, 50, 51, 123456789, time.UTC),
		"non-UTC offset":     time.Date(2026, 7, 20, 16, 50, 51, 0, zone),
		"both":               time.Date(2026, 7, 20, 16, 50, 51, 987654321, zone),
	} {
		t.Run(name, func(t *testing.T) {
			signed, err := Sign(Manifest{
				Context:        ContextURI,
				Type:           ManifestType,
				Asset:          Asset{SHA256: strings.Repeat("a", 64), Size: 1, MIME: "text/markdown"},
				ClaimGenerator: "Test/1",
				GeneratorInfo:  GeneratorInfo{Name: "Test", Version: "1"},
				CreatedAt:      in,
				Assertions:     []Assertion{},
			}, key)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			wire, err := json.Marshal(signed)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got struct {
				CreatedAt string `json:"created_at"`
			}
			if err := json.Unmarshal(wire, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if want := "2026-07-20T14:50:51Z"; got.CreatedAt != want {
				t.Fatalf("wire created_at = %q, want %q", got.CreatedAt, want)
			}
			if err := Verify(signed); err != nil {
				t.Fatalf("verify: %v", err)
			}
		})
	}
}

// A credential whose `created_at` is not whole-second UTC is not a
// conforming credential, and is rejected before any signature work.
func TestVerifyRejectsNonWholeSecondCreatedAt(t *testing.T) {
	key := testKey(t)
	base, err := Build(BuildInput{
		Asset:     Asset{SHA256: strings.Repeat("a", 64), Size: 1, MIME: "text/markdown"},
		Generator: GeneratorInfo{Name: "Folio", Version: "0.1.0"},
		CreatedAt: time.Date(2026, 7, 20, 14, 50, 51, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	signed, err := Sign(base, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	wire, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for name, replacement := range map[string]string{
		"fractional seconds": `"2026-07-20T14:50:51.5Z"`,
		"non-UTC offset":     `"2026-07-20T16:50:51+02:00"`,
		"zero offset not Z":  `"2026-07-20T14:50:51+00:00"`,
	} {
		t.Run(name, func(t *testing.T) {
			tampered := strings.Replace(string(wire),
				`"created_at":"2026-07-20T14:50:51Z"`,
				`"created_at":`+replacement, 1)
			if tampered == string(wire) {
				t.Fatal("test fixture did not contain the expected created_at field")
			}
			var parsed SignedManifest
			if err := json.Unmarshal([]byte(tampered), &parsed); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			err := Verify(parsed)
			if err == nil {
				t.Fatal("expected a non-whole-second UTC created_at to be rejected")
			}
			if !strings.Contains(err.Error(), "created_at") {
				t.Fatalf("error %q does not name the offending field", err)
			}
		})
	}
}
