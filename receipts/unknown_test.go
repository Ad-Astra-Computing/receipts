// SPDX-License-Identifier: Apache-2.0

package receipts

import (
	"encoding/json"
	"strings"
	"testing"
)

// The signing digest covers a fixed list of fields, so any member a
// producer adds outside that list rides along unsigned. Accepting one
// would let a bundle carry content nobody signed while the page reports
// that nothing in the receipt was altered. For schema 1 the answer is to
// refuse: forward compatibility belongs to a new schema string, not to
// unsigned members of this one.
func TestBundleRejectsUnknownMembers(t *testing.T) {
	for name, body := range map[string]string{
		"at the top level":   `{"schema":"folio.receipts/1","generated":"2026-01-01T00:00:00Z","surprise":1}`,
		"inside post":        `{"schema":"folio.receipts/1","generated":"2026-01-01T00:00:00Z","post":{"title":"t","surprise":1}}`,
		"inside timeline":    `{"schema":"folio.receipts/1","generated":"2026-01-01T00:00:00Z","timeline":{"checkpoints":[],"surprise":1}}`,
		"inside checkpoint":  `{"schema":"folio.receipts/1","generated":"2026-01-01T00:00:00Z","timeline":{"checkpoints":[{"at":"2026-01-01T00:00:00Z","words":1,"chars":1,"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","surprise":1}]}}`,
		"inside an ai range": `{"schema":"folio.receipts/1","generated":"2026-01-01T00:00:00Z","ai_ranges":[{"from":1,"to":2,"surprise":1}]}`,
		"inside signature":   `{"schema":"folio.receipts/1","generated":"2026-01-01T00:00:00Z","signature":{"alg":"Ed25519","surprise":1}}`,
	} {
		t.Run(name, func(t *testing.T) {
			var b Bundle
			err := json.Unmarshal([]byte(body), &b)
			if err == nil {
				t.Fatal("accepted a member the signature does not cover")
			}
			if !strings.Contains(err.Error(), "surprise") {
				t.Fatalf("error %q does not name the offending member", err)
			}
		})
	}
}

func TestBundleAcceptsTheFieldsItDefines(t *testing.T) {
	body := `{"schema":"folio.receipts/1","generated":"2026-01-01T00:00:00Z",
	  "post":{"title":"t","url":"https://example.com","sha256":"abc"},
	  "ai_ranges":[{"from":1,"to":2,"model":"m","when":"2026-01-01T00:00:00Z"}],
	  "claims":[{"excerpt":"e","source_url":"https://example.org","status":"supported"}],
	  "timeline":{"checkpoints":[{"at":"2026-01-01T00:00:00Z","words":1,"chars":1,"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"chain_hash":"c"},
	  "signature":{"alg":"Ed25519","public_key":"k","value":"v"}}`
	var b Bundle
	if err := json.Unmarshal([]byte(body), &b); err != nil {
		t.Fatalf("rejected a conforming bundle: %v", err)
	}
	if b.Post.Title != "t" || len(b.Timeline.Checkpoints) != 1 || b.Signature.Alg != "Ed25519" {
		t.Fatalf("fields did not survive: %+v", b)
	}
}
