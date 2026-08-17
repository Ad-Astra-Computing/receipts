// SPDX-License-Identifier: Apache-2.0

package receipts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// SPEC.md section 4 requires every wire timestamp to be RFC 3339 in UTC,
// whole seconds, with the Z designator, because the chain hashes the
// rendered string. Anything else has to be refused at the door: this
// implementation hashes a normalized form, so an offset or a fractional
// second would be hashed as something other than what the bundle says,
// and a verifier that hashes the literal string (the TypeScript one does)
// would reach the opposite verdict on the same bytes.
func TestCheckpointRejectsNonCanonicalTimestamps(t *testing.T) {
	for _, tc := range []struct {
		name string
		at   string
	}{
		{"offset instead of Z", "2026-01-01T05:00:00+05:00"},
		{"negative offset", "2026-01-01T00:00:00-08:00"},
		{"fractional seconds", "2026-01-01T00:00:00.5Z"},
		{"nanoseconds", "2026-01-01T00:00:00.123456789Z"},
		{"lowercase z", "2026-01-01T00:00:00z"},
		{"space instead of T", "2026-01-01 00:00:00Z"},
		{"date only", "2026-01-01"},
		{"empty", ""},
		{"not a time at all", "yesterday"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"at":` + mustJSON(t, tc.at) + `,"words":1,"chars":1,"hash":"abc"}`
			var cp Checkpoint
			if err := json.Unmarshal([]byte(body), &cp); err == nil {
				t.Fatalf("accepted non-canonical timestamp %q; want an error", tc.at)
			}
		})
	}
}

func TestCheckpointAcceptsCanonicalTimestamp(t *testing.T) {
	const at = "2026-01-01T00:00:00Z"
	var cp Checkpoint
	if err := json.Unmarshal([]byte(`{"at":"`+at+`","words":3,"chars":9,"hash":"abc"}`), &cp); err != nil {
		t.Fatalf("rejected canonical timestamp: %v", err)
	}
	if cp.Words != 3 || cp.Chars != 9 || cp.Hash != "abc" {
		t.Fatalf("other fields did not survive: %+v", cp)
	}
	// Round-tripping must reproduce the exact bytes that were hashed.
	out, err := json.Marshal(cp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(out), `"at":"`+at+`"`) {
		t.Fatalf("round trip changed the timestamp: %s", out)
	}
}

// The whole point of the restriction: the string the chain hashes is the
// string on the wire, so the two implementations cannot disagree.
func TestChainHashesTheWireTimestamp(t *testing.T) {
	const at = "2026-01-01T00:00:00Z"
	var cp Checkpoint
	if err := json.Unmarshal([]byte(`{"at":"`+at+`","words":1,"chars":1,"hash":"h"}`), &cp); err != nil {
		t.Fatal(err)
	}
	got := ChainCheckpoint("", cp)
	want := sha256HexOf("" + "|" + at + "|1|1|h")
	if got != want {
		t.Fatalf("chain hashed something other than the wire timestamp:\n got %s\nwant %s", got, want)
	}
}

func sha256HexOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func mustJSON(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
