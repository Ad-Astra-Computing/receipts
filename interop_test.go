// SPDX-License-Identifier: Apache-2.0

// Package receipts_test holds the cross-language interop gate, which has
// two halves because agreement has two halves.
//
// Agreement on what is VALID: a bundle signed here must verify in the
// reference TypeScript verifier (TestGoSignedBundleVerifiesInTypeScript).
//
// Agreement on what is INVALID: both implementations must refuse every
// case in testdata/rejections.json (corpus_test.go here, corpus.test.ts
// there). This half is the one that was missing, and its absence is why
// offset timestamps, padded base64 and unsigned extra members could be
// accepted by one side and refused by the other without any gate
// noticing.
package receipts_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Ad-Astra-Computing/receipts/receipts"
)

// TestGoSignedBundleVerifiesInTypeScript signs a fresh bundle with the
// Go module and runs the browser verifier's own test suite against it.
// If the two implementations ever disagree on the signing digest, the
// timeline chain or the credential canonicalization, this fails.
func TestGoSignedBundleVerifiesInTypeScript(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the Node interop gate in short mode")
	}
	npm, err := exec.LookPath("npm")
	if err != nil {
		t.Skip("npm is not on PATH")
	}
	if _, err := os.Stat(filepath.Join("verifier", "node_modules", "vitest")); err != nil {
		t.Skip("verifier dependencies are not installed (run: cd verifier && npm ci)")
	}

	fixture := filepath.Join(t.TempDir(), "go-signed.json")
	gen := exec.Command("go", "run", "./verifier/gen", "-o", fixture)
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("generate fixture: %v\n%s", err, out)
	}

	// The Go verifier accepts it first, so a failure downstream is a
	// disagreement between implementations and not a broken fixture.
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var parsed struct {
		Bundle receipts.Bundle `json:"bundle"`
		Body   string          `json:"body"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if err := receipts.VerifyBody(parsed.Bundle, []byte(parsed.Body)); err != nil {
		t.Fatalf("Go verifier rejected its own bundle: %v", err)
	}

	cmd := exec.Command(npm, "test", "--silent")
	cmd.Dir = "verifier"
	cmd.Env = append(os.Environ(), "RECEIPTS_FIXTURE="+fixture)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the TypeScript verifier rejected a Go-signed bundle: %v\n%s", err, out)
	}
	t.Logf("verifier suite against the Go-signed fixture:\n%s", out)
}

// TestTypeScriptSignedBundleVerifiesInGo is the other direction, and it
// is the one that was missing.
//
// The test above proves the browser accepts what Go produces. That says
// nothing about whether Go accepts what the browser produces, and the
// specification invites people to write producers in whatever language
// they like. A canonicalization or digest difference that only shows up
// when TypeScript is the signer would have been invisible to a gate
// that only ever ran one way.
func TestTypeScriptSignedBundleVerifiesInGo(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the Node interop gate in short mode")
	}
	npm, err := exec.LookPath("npm")
	if err != nil {
		t.Skip("npm is not on PATH")
	}
	if _, err := os.Stat(filepath.Join("verifier", "node_modules", "vitest")); err != nil {
		t.Skip("verifier dependencies are not installed (run: cd verifier && npm ci)")
	}

	fixture := filepath.Join(t.TempDir(), "ts-signed.json")
	gen := exec.Command(npm, "run", "--silent", "test:produce")
	gen.Dir = "verifier"
	gen.Env = append(os.Environ(), "RECEIPTS_TS_FIXTURE="+fixture)
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("produce a TypeScript-signed bundle: %v\n%s", err, out)
	}

	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var parsed struct {
		Bundle json.RawMessage `json:"bundle"`
		Body   string          `json:"body"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	// Through Decode, the same entry point a verifier uses on a file,
	// so the strict parse rules apply rather than a lenient unmarshal.
	envelope, err := json.Marshal(map[string]any{
		"bundle": json.RawMessage(parsed.Bundle),
		"body":   parsed.Body,
	})
	if err != nil {
		t.Fatalf("re-marshal envelope: %v", err)
	}
	bundle, body, err := receipts.Decode(envelope)
	if err != nil {
		t.Fatalf("Go refused a bundle the TypeScript implementation signed: %v", err)
	}
	if err := receipts.VerifyBody(bundle, body); err != nil {
		t.Fatalf("Go failed to verify a TypeScript-signed bundle against its body: %v", err)
	}
}
