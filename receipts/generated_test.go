// SPDX-License-Identifier: Apache-2.0

package receipts_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Ad-Astra-Computing/receipts/receipts"
)

// wireGenerated marshals b and returns the exact `generated` string a
// verifier in another language would hash.
func wireGenerated(t *testing.T, b receipts.Bundle) string {
	t.Helper()
	wire, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got struct {
		Generated string `json:"generated"`
	}
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return got.Generated
}

// SPEC.md section 3 requires whole-second UTC timestamps, and the
// signing digest (section 6) hashes the rendered `generated` string.
// A producer that hands Sign an un-truncated or non-UTC time must not
// be able to emit a bundle whose wire form differs from the string the
// signature covers: Go would accept it and a browser hashing the wire
// string would reject it.
func TestSignNormalizesGenerated(t *testing.T) {
	key := testKey(t)
	zone := time.FixedZone("CET", 2*60*60)
	for name, in := range map[string]time.Time{
		"fractional seconds": time.Date(2026, 7, 20, 14, 50, 51, 123456789, time.UTC),
		"non-UTC offset":     time.Date(2026, 7, 20, 16, 50, 51, 0, zone),
		"both":               time.Date(2026, 7, 20, 16, 50, 51, 987654321, zone),
	} {
		t.Run(name, func(t *testing.T) {
			b := buildBundle(t, key, sampleBody)
			b.Generated = in
			signed, err := receipts.Sign(b, key)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			want := "2026-07-20T14:50:51Z"
			if got := wireGenerated(t, signed); got != want {
				t.Fatalf("wire generated = %q, want %q", got, want)
			}
			if err := receipts.Verify(signed); err != nil {
				t.Fatalf("verify: %v", err)
			}
		})
	}
}

// A bundle whose `generated` arrives with sub-second precision or a
// non-Z offset must be rejected outright. The Go signing digest renders
// the timestamp before hashing, so without this check such a bundle
// verifies here and fails in the browser, which hashes the wire string.
//
// The refusal happens at parse rather than at Verify: a bundle that
// cannot be spoken about consistently should not become a value that
// later code has to keep remembering to distrust.
func TestVerifyRejectsNonWholeSecondGenerated(t *testing.T) {
	key := testKey(t)
	for name, replacement := range map[string]string{
		"fractional seconds": `"2026-07-20T14:50:51.5Z"`,
		"non-UTC offset":     `"2026-07-20T16:50:51+02:00"`,
		"zero offset not Z":  `"2026-07-20T14:50:51+00:00"`,
	} {
		t.Run(name, func(t *testing.T) {
			b := buildBundle(t, key, sampleBody)
			wire, err := json.Marshal(b)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			tampered := strings.Replace(string(wire),
				`"generated":"2026-07-20T14:50:51Z"`,
				`"generated":`+replacement, 1)
			if tampered == string(wire) {
				t.Fatal("test fixture did not contain the expected generated field")
			}
			var parsed receipts.Bundle
			err = json.Unmarshal([]byte(tampered), &parsed)
			if err == nil {
				t.Fatal("expected a non-whole-second UTC generated to be rejected")
			}
			if !strings.Contains(err.Error(), "generated") &&
				!strings.Contains(err.Error(), replacement[1:len(replacement)-1]) {
				t.Fatalf("error %q names neither the field nor the offending value", err)
			}
		})
	}
}
