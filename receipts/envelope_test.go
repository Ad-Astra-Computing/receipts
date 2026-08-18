// SPDX-License-Identifier: Apache-2.0

package receipts_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Ad-Astra-Computing/receipts/receipts"
)

func fixtureFile(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "verifier", "src", "testdata", "sample-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// SPEC 3a: a verifier must accept both the envelope and a bare bundle.
func TestVerifyFileAcceptsBothForms(t *testing.T) {
	envelope := fixtureFile(t)

	b, bodyChecked, err := receipts.VerifyFile(envelope)
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	if !bodyChecked {
		t.Fatal("an envelope carries a body, so the body must have been checked")
	}
	if b.Schema != receipts.Schema {
		t.Fatalf("schema not decoded: %q", b.Schema)
	}

	var wrapper struct {
		Bundle json.RawMessage `json:"bundle"`
	}
	if err := json.Unmarshal(envelope, &wrapper); err != nil {
		t.Fatal(err)
	}
	if _, bodyChecked, err := receipts.VerifyFile(wrapper.Bundle); err != nil {
		t.Fatalf("bare bundle: %v", err)
	} else if bodyChecked {
		t.Fatal("a bare bundle has no body, so nothing can have been compared")
	}
}

// The envelope is not a way to smuggle members into a bundle.
func TestDecodeRejectsAnEnvelopeWithExtras(t *testing.T) {
	var obj map[string]any
	if err := json.Unmarshal(fixtureFile(t), &obj); err != nil {
		t.Fatal(err)
	}
	obj["surprise"] = 1
	raw, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := receipts.Decode(raw); err == nil {
		t.Fatal("accepted an envelope carrying an unexpected member")
	}
}

func TestDecodeRejectsANonStringBody(t *testing.T) {
	var obj map[string]any
	if err := json.Unmarshal(fixtureFile(t), &obj); err != nil {
		t.Fatal(err)
	}
	obj["body"] = 42
	raw, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := receipts.Decode(raw); err == nil {
		t.Fatal("accepted an envelope whose body is not text")
	}
}
