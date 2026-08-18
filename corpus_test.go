// SPDX-License-Identifier: Apache-2.0

package receipts_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ad-Astra-Computing/receipts/receipts"
)

type rejectionCase struct {
	Name   string          `json:"name"`
	Why    string          `json:"why"`
	Path   string          `json:"path"`
	Set    json.RawMessage `json:"set"`
	Delete bool            `json:"delete"`
	// Raw cases mutate the serialized text, for properties a parse
	// destroys: duplicate members and lone surrogates.
	Raw *struct {
		Duplicate    string `json:"duplicate"`
		InjectString *struct {
			Find    string `json:"find"`
			Replace string `json:"replace"`
		} `json:"injectString"`
	} `json:"raw"`
}

// TestRejectionCorpus applies each shared mutation to the verifier
// fixture and requires this implementation to refuse it. The TypeScript
// suite reads the same file and makes the same demand.
//
// What this establishes, exactly: the two agree about the inputs listed
// in testdata/rejections.json. It does not establish that they agree
// about every possible input, and saying so would be the kind of
// unearned claim this project exists to avoid. The corpus grows when a
// divergence is found; every case in it is a divergence that was found.
func TestRejectionCorpus(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "rejections.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []rejectionCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) == 0 {
		t.Fatal("the corpus is empty")
	}

	fixtureRaw, err := os.ReadFile(filepath.Join("verifier", "src", "testdata", "sample-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Bundle json.RawMessage `json:"bundle"`
	}
	if err := json.Unmarshal(fixtureRaw, &fixture); err != nil {
		t.Fatal(err)
	}

	// The unmutated fixture must verify, or every case below passes for
	// the wrong reason.
	var clean receipts.Bundle
	if err := json.Unmarshal(fixture.Bundle, &clean); err != nil {
		t.Fatalf("the fixture itself does not parse: %v", err)
	}
	if err := receipts.Verify(clean); err != nil {
		t.Fatalf("the fixture itself does not verify: %v", err)
	}

	for _, c := range corpus.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if c.Raw != nil {
				text := string(fixture.Bundle)
				switch {
				case c.Raw.Duplicate != "":
					// Repeat a member by reopening the object.
					needle := `"` + c.Raw.Duplicate + `":`
					idx := strings.Index(text, needle)
					if idx < 0 {
						t.Fatalf("%q is not in the fixture", c.Raw.Duplicate)
					}
					text = text[:idx] + needle + `"repeated",` + text[idx:]
				case c.Raw.InjectString != nil:
					if !strings.Contains(text, c.Raw.InjectString.Find) {
						t.Fatalf("%q is not in the fixture", c.Raw.InjectString.Find)
					}
					text = strings.Replace(text, c.Raw.InjectString.Find, c.Raw.InjectString.Replace, 1)
				}
				if _, _, err := receipts.Decode([]byte(text)); err == nil {
					t.Fatalf("accepted %q; %s", c.Name, c.Why)
				}
				return
			}
			var obj map[string]any
			if err := json.Unmarshal(fixture.Bundle, &obj); err != nil {
				t.Fatal(err)
			}
			mutate(t, obj, strings.Split(c.Path, "."), c)
			mutated, err := json.Marshal(obj)
			if err != nil {
				t.Fatal(err)
			}
			var b receipts.Bundle
			if err := json.Unmarshal(mutated, &b); err != nil {
				return // refused at parse, which is a refusal
			}
			if err := receipts.Verify(b); err == nil {
				t.Fatalf("accepted %q; %s", c.Name, c.Why)
			}
		})
	}
}

// mutate walks path and applies the case's change. "PADDED" is a stand-in
// the corpus uses for "this value, re-spelled with base64 padding", which
// cannot be written literally without hard-coding a signature.
func mutate(t *testing.T, obj map[string]any, path []string, c rejectionCase) {
	t.Helper()
	cur := any(obj)
	for i, seg := range path {
		last := i == len(path)-1
		switch node := cur.(type) {
		case map[string]any:
			if last {
				if c.Delete {
					delete(node, seg)
					return
				}
				node[seg] = value(t, node[seg], c)
				return
			}
			next, ok := node[seg]
			if !ok {
				t.Fatalf("path %q: %q is not in the fixture", c.Path, seg)
			}
			cur = next
		case []any:
			idx := 0
			if _, err := fmt.Sscanf(seg, "%d", &idx); err != nil || idx >= len(node) {
				t.Fatalf("path %q: %q is not an index into a %d-element array", c.Path, seg, len(node))
			}
			if last {
				node[idx] = value(t, node[idx], c)
				return
			}
			cur = node[idx]
		default:
			t.Fatalf("path %q: %q is not a container", c.Path, seg)
		}
	}
}

func value(t *testing.T, existing any, c rejectionCase) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(c.Set, &v); err != nil {
		t.Fatalf("case %q has an unreadable `set`: %v", c.Name, err)
	}
	if s, ok := v.(string); ok && s == "PADDED" {
		cur, _ := existing.(string)
		return cur + "="
	}
	return v
}
