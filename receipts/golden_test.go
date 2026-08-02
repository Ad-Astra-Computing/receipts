// SPDX-License-Identifier: Apache-2.0

package receipts_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Ad-Astra-Computing/receipts/receipts"
)

// The golden vectors are bundles the reference TypeScript verifier
// accepts. Verifying them here pins both implementations to one
// format: a change to the Go signing digest, the timeline chain or the
// credential canonicalization breaks these before it can reach a
// published bundle.
type fixture struct {
	Bundle receipts.Bundle `json:"bundle"`
	Body   string          `json:"body"`
}

func loadGolden(t *testing.T, name string) fixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "golden", name))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var f fixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	return f
}

func TestGoldenVectorsVerify(t *testing.T) {
	for _, name := range []string{"sample-bundle.json", "sample-hero.json"} {
		t.Run(name, func(t *testing.T) {
			f := loadGolden(t, name)
			if err := receipts.VerifyBody(f.Bundle, []byte(f.Body)); err != nil {
				t.Fatalf("golden bundle failed verification: %v", err)
			}
		})
	}
}

func TestGoldenVectorRejectsTamperedBody(t *testing.T) {
	f := loadGolden(t, "sample-bundle.json")
	if err := receipts.VerifyBody(f.Bundle, []byte(f.Body+" tampered")); err == nil {
		t.Fatal("expected a tampered body to be rejected")
	}
}

func TestGoldenVectorRejectsMutatedCredentialField(t *testing.T) {
	// Rewrite a credential content field in the wire JSON, leaving
	// signature.value alone. The credential's own signature must catch
	// it, which is the whole reason SPEC.md section 8 step 5 exists.
	data, err := os.ReadFile(filepath.Join("..", "testdata", "golden", "sample-bundle.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	tampered := bytes.Replace(data, []byte(`"claim_generator": "Folio/0.1.0"`),
		[]byte(`"claim_generator": "Impostor/9.9.9"`), 1)
	if bytes.Equal(tampered, data) {
		t.Fatal("golden vector did not contain the field to tamper with")
	}
	var f fixture
	if err := json.Unmarshal(tampered, &f); err != nil {
		t.Fatalf("parse tampered golden: %v", err)
	}
	if err := receipts.Verify(f.Bundle); err == nil {
		t.Fatal("expected a mutated credential content field to be rejected")
	}
}

func TestGoldenVectorRejectsReorderedTimeline(t *testing.T) {
	f := loadGolden(t, "sample-bundle.json")
	cps := f.Bundle.Timeline.Checkpoints
	if len(cps) < 2 {
		t.Skip("golden vector has too few checkpoints")
	}
	cps[0], cps[1] = cps[1], cps[0]
	if err := receipts.Verify(f.Bundle); err == nil {
		t.Fatal("expected a reordered timeline to be rejected")
	}
}
