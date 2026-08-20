// SPDX-License-Identifier: Apache-2.0

package receipts_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Ad-Astra-Computing/receipts/receipts"
)

// FuzzDecodeNeverPanics feeds arbitrary bytes to the entry point a
// verifier actually calls on a file somebody handed it.
//
// The contract being tested is narrow and absolute: Decode either
// returns a bundle or returns an error. It never panics, however
// malformed, truncated, deeply nested or hostile the input. A parser
// published for other people to run against files they did not write
// has no business crashing on one, and a panic in a verifier is worse
// than a wrong answer: it takes the process with it.
//
// `go test` runs only the seed corpus, which is cheap and keeps the
// gate honest in CI. Run the real thing with:
//
//	go test -run XXX -fuzz FuzzDecodeNeverPanics -fuzztime 5m .
func FuzzDecodeNeverPanics(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("{"))
	f.Add([]byte("null"))
	f.Add([]byte(`{"bundle":null,"body":null}`))
	f.Add([]byte(`{"bundle":{},"body":""}`))
	f.Add([]byte(`{"bundle":{"schema":"folio.receipts/1"},"body":"x"}`))

	// The golden vectors: real signed envelopes, in the exact shape a
	// verifier is handed. They are the best seeds available because a
	// mutation of a valid document reaches deep into the parser, where a
	// mutation of noise is rejected at the first byte.
	//
	// The shared rejection corpus is deliberately NOT seeded from: its
	// `raw` member is a mutation instruction rather than a document, so
	// feeding it here would add nothing but look like coverage.
	for _, name := range []string{"sample-bundle.json", "sample-hero.json"} {
		if raw, err := os.ReadFile(filepath.Join("testdata", "golden", name)); err == nil {
			f.Add(raw)
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// The result is deliberately ignored: any return value is
		// acceptable, and only a panic fails this test.
		_, _, _ = receipts.Decode(data)
	})
}
