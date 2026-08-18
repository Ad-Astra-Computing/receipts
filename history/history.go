// SPDX-License-Identifier: Apache-2.0

// Package history holds the portable composition snapshot and turns a
// run of snapshots into the timeline digest a receipts bundle carries.
//
// A snapshot is a checkpoint of a document as it was being written. It
// keeps the draft text so the tool that captured it can replay the
// composition locally. Digesting drops the text: what travels with a
// published piece is the count and hash of each checkpoint, chained,
// never the drafts themselves.
//
// The package is pure. Capturing snapshots, storing them and deciding
// which to keep are the producer's business.
package history

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
	"unicode/utf8"

	"github.com/Ad-Astra-Computing/receipts/receipts"
)

// Snapshot is one checkpoint of a document's body.
type Snapshot struct {
	At    time.Time `json:"at"`
	Words int       `json:"words"`
	Chars int       `json:"chars"` // rune count of the full body
	Hash  string    `json:"hash"`  // sha256 hex of the full body
	Text  string    `json:"text"`  // body at this point, as the producer stored it
}

// NewSnapshot measures text and returns the snapshot describing it at
// time at. Text is carried through unchanged; a producer that caps or
// omits it sets the field itself afterwards.
func NewSnapshot(at time.Time, text string) Snapshot {
	sum := sha256.Sum256([]byte(text))
	return Snapshot{
		At:    at.UTC(),
		Words: WordCount(text),
		// Code points, per SPEC section 4: a size the author sees, so it
		// counts characters. Not to be confused with ai_ranges offsets,
		// which are byte positions a machine resolves.
		Chars: utf8.RuneCountInString(text),
		Hash:  hex.EncodeToString(sum[:]),
		Text:  text,
	}
}

// DigestTimeline drops the draft text and returns the tamper-evident
// timeline digest for the bundle.
func DigestTimeline(snaps []Snapshot) receipts.TimelineDigest {
	cps := make([]receipts.Checkpoint, 0, len(snaps))
	for _, s := range snaps {
		cps = append(cps, receipts.Checkpoint{
			At:    s.At,
			Words: s.Words,
			Chars: s.Chars,
			Hash:  s.Hash,
		})
	}
	return receipts.DigestTimeline(cps)
}

// WordCount counts whitespace-separated words, the measure the
// timeline checkpoints record.
func WordCount(s string) int {
	n := 0
	inWord := false
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', '\f', '\v':
			inWord = false
		default:
			if !inWord {
				n++
				inWord = true
			}
		}
	}
	return n
}
