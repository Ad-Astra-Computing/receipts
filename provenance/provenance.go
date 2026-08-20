// SPDX-License-Identifier: Apache-2.0

// Package provenance defines the append-only event chain that records
// which spans of a document came from an AI tool, and the hash chain
// that makes the record tamper-evident.
//
// The package is pure: it holds the wire types and the chain
// arithmetic, and it never touches a disk, a workspace or a network.
// A producer keeps its own storage and calls Append for each new
// event; a verifier calls VerifyChain over the events it was given.
package provenance

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// Kind classifies a provenance event.
type Kind string

const (
	// KindAIWrite: a range was pasted from an external AI tool. The
	// writer chose this content deliberately and is disclosing it.
	KindAIWrite Kind = "ai-write"
	// KindHumanEdit: the writer subsequently edited an AI-written
	// range. Stored so a reader can see "AI wrote X, then a human
	// modified it".
	KindHumanEdit Kind = "human-edit"
	// KindRemove: a previously marked AI range was unmarked. Stored
	// rather than mutated so the chain stays append-only.
	KindRemove Kind = "remove"
)

// SchemaVersion is the manifest schema version a producer stamps on
// its stored events.
const SchemaVersion = 1

// Span is a content range. Both the byte offsets and the raw text are
// carried so a verifier does not need to re-parse the document.
type Span struct {
	From int    `json:"from"`
	To   int    `json:"to"`
	Text string `json:"text"`
}

// Event is one record on a document's provenance timeline.
type Event struct {
	ID    string    `json:"id"`
	Kind  Kind      `json:"kind"`
	At    time.Time `json:"at"`
	Model string    `json:"model,omitempty"`
	// Prompt is an optional, user-supplied summary of what was asked.
	Prompt string `json:"prompt,omitempty"`
	// Span identifies the affected text range. For KindAIWrite this is
	// the exact text the writer marked. For KindRemove only TargetID
	// is meaningful.
	Span Span `json:"span,omitempty"`
	// TargetID references a previous event (KindRemove, KindHumanEdit).
	TargetID string `json:"targetId,omitempty"`
	// Hash is the running chain value: SHA-256 hex of
	// (prev || a deterministic encoding of the event without Hash (see canonicalize below: maps become sorted alternating key/value arrays, which is NOT RFC 8785 canonical JSON)).
	Hash string `json:"hash"`
}

// Digest computes the chain value for ev following prev. The event's
// own Hash field is excluded from the encoding, so the value is a
// function of the event payload and not of itself.
func Digest(prev string, ev Event) string {
	clone := ev
	clone.Hash = ""
	payload := map[string]any{
		"id": clone.ID, "kind": clone.Kind, "at": clone.At.Format(time.RFC3339Nano),
		"model": clone.Model, "prompt": clone.Prompt,
		"span":     clone.Span,
		"targetId": clone.TargetID,
	}
	bs, _ := json.Marshal(canonicalize(payload))
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write(bs)
	return hex.EncodeToString(h.Sum(nil))
}

// canonicalize flattens maps into key-sorted alternating key/value
// slices so the encoding is deterministic regardless of Go map order.
func canonicalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make([]any, 0, len(keys)*2)
		for _, k := range keys {
			out = append(out, k, canonicalize(t[k]))
		}
		return out
	default:
		return v
	}
}

// Append returns ev completed for storage after the chain value prev:
// a generated ID when it has none, a UTC timestamp, and the chain
// hash. Pass the empty string as prev for the first event of a
// document. The caller persists the returned event.
func Append(prev string, ev Event) Event {
	if ev.At.IsZero() {
		ev.At = time.Now().UTC()
	} else {
		ev.At = ev.At.UTC()
	}
	if ev.ID == "" {
		ev.ID = NewID()
	}
	ev.Hash = Digest(prev, ev)
	return ev
}

// PrevHash returns the chain value of the last event, or the empty
// string when there are none.
func PrevHash(evs []Event) string {
	if len(evs) == 0 {
		return ""
	}
	return evs[len(evs)-1].Hash
}

// VerifyChain replays the chain and returns an error naming the first
// event whose recorded hash does not match recomputation. A nil return
// proves the chain is internally consistent; it does not prove the
// events describe the document they travel with.
func VerifyChain(evs []Event) error {
	prev := ""
	for i, ev := range evs {
		if want := Digest(prev, ev); want != ev.Hash {
			return fmt.Errorf("provenance: chain break at event %d (%s)", i, ev.ID)
		}
		prev = ev.Hash
	}
	return nil
}

// NewID generates a 12-hex-character event identifier.
func NewID() string {
	var buf [8]byte
	_, _ = cryptorand.Read(buf[:])
	now := time.Now().UnixNano()
	h := sha256.Sum256(append(buf[:], byte(now), byte(now>>8), byte(now>>16), byte(now>>24)))
	return hex.EncodeToString(h[:6])
}
