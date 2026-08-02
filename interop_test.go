// SPDX-License-Identifier: Apache-2.0

// Package receipts_test holds the cross-language interop gate: a
// bundle signed here must verify in the reference TypeScript verifier,
// and a bundle the verifier accepts must verify here.
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
