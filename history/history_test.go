// SPDX-License-Identifier: Apache-2.0

package history

import (
	"strings"
	"testing"
	"time"

	"github.com/Ad-Astra-Computing/receipts/receipts"
)

func TestNewSnapshotMeasuresBody(t *testing.T) {
	at := time.Date(2026, 7, 20, 13, 0, 0, 0, time.UTC)
	s := NewSnapshot(at, "héllo wörld")
	if s.Words != 2 {
		t.Fatalf("words = %d, want 2", s.Words)
	}
	if s.Chars != 11 {
		t.Fatalf("chars = %d, want 11 runes", s.Chars)
	}
	if len(s.Hash) != 64 {
		t.Fatalf("hash = %q", s.Hash)
	}
	if s.Text != "héllo wörld" {
		t.Fatalf("text not carried through: %q", s.Text)
	}
}

func TestDigestTimelineDropsDraftText(t *testing.T) {
	at := time.Date(2026, 7, 20, 13, 0, 0, 0, time.UTC)
	snaps := []Snapshot{
		NewSnapshot(at, "a first draft"),
		NewSnapshot(at.Add(time.Minute), "a first draft, then a second"),
	}
	d := DigestTimeline(snaps)
	if len(d.Checkpoints) != 2 {
		t.Fatalf("checkpoints = %d, want 2", len(d.Checkpoints))
	}
	if !receipts.VerifyTimeline(d) {
		t.Fatal("digested timeline does not verify")
	}
	for _, cp := range d.Checkpoints {
		if cp.Hash == "" || cp.Words == 0 {
			t.Fatalf("checkpoint lost its measurements: %+v", cp)
		}
	}
	// No draft text can survive into the digest: the whole point of
	// the format is that the timeline is a digest, never the drafts.
	for _, snap := range snaps {
		for _, cp := range d.Checkpoints {
			if strings.Contains(cp.Hash, snap.Text) {
				t.Fatal("draft text leaked into the digest")
			}
		}
	}
}

func TestWordCount(t *testing.T) {
	cases := map[string]int{
		"":                  0,
		"   ":               0,
		"one":               1,
		" one  two\tthree ": 3,
		"line\nbreak":       2,
	}
	for in, want := range cases {
		if got := WordCount(in); got != want {
			t.Fatalf("WordCount(%q) = %d, want %d", in, got, want)
		}
	}
}

// SPEC section 3.2 fixes the word separators as exactly six ASCII
// characters, because this count is hashed into the timeline chain and
// "Unicode whitespace" would make it depend on which table version an
// implementation consulted. These cases pin that decision, including the
// limitation it accepts.
func TestWordCountSeparatorsAreExactlyTheSpecifiedSix(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		want int
	}{
		"spaces":                  {"one two three", 3},
		"tab":                     {"one\ttwo", 2},
		"newline":                 {"one\ntwo", 2},
		"carriage return":         {"one\rtwo", 2},
		"form feed":               {"one\ftwo", 2},
		"vertical tab":            {"one\vtwo", 2},
		"runs collapse":           {"one   \n\t two", 2},
		"leading and trailing":    {"  one  ", 1},
		"empty":                   {"", 0},
		"punctuation attaches":    {"hello, world!", 2},
		"hyphenated is one":       {"well-known", 1},
		"no-break space does not": {"one two", 1},
		"ideographic space not":   {"one　two", 1},
	} {
		t.Run(name, func(t *testing.T) {
			if got := WordCount(tc.in); got != tc.want {
				t.Fatalf("WordCount(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}
