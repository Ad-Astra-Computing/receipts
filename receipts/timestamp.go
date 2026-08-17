// SPDX-License-Identifier: Apache-2.0

package receipts

import (
	"encoding/json"
	"fmt"
	"time"
)

// Every timestamp this format hashes is hashed as a RENDERED STRING: the
// timeline chain hashes `at` (section 5) and the signing digest hashes
// `generated` (section 6). Section 4 therefore fixes one wire form, RFC
// 3339 in UTC, whole seconds, `Z` designator, and this file is where that
// is enforced on the way in.
//
// Enforcing it matters more than it looks. This implementation renders a
// timestamp from a parsed time.Time before hashing, so given
// "2026-01-01T05:00:00+05:00" it would hash "2026-01-01T00:00:00Z": not
// the string in the file. A verifier that hashes the literal wire string,
// which is the natural thing to do and what the TypeScript verifier does,
// would hash the offset form. The same bundle would then verify in one
// implementation and fail in the other, and a format whose whole promise
// is that anyone can write a verifier cannot afford that. So a
// non-canonical timestamp is not normalized on the way in, it is refused.

// canonicalTimestamp parses a wire timestamp and rejects any rendering
// other than the one section 4 requires.
//
// The test is a round trip rather than a pattern: a string is canonical
// exactly when re-rendering the time it parses to reproduces it. That
// catches offsets, fractional seconds and any other spelling in one
// comparison, and it cannot drift from what the hashing code renders,
// because it calls the same formatter.
func canonicalTimestamp(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("timestamp %q is not RFC 3339: %w", s, err)
	}
	if got := t.UTC().Format(time.RFC3339); got != s {
		return time.Time{}, fmt.Errorf(
			"timestamp %q is not in the canonical wire form (want %q): SPEC.md section 4 requires UTC, whole seconds and the Z designator, because the chain hashes this string",
			s, got,
		)
	}
	return t, nil
}

// UnmarshalJSON refuses a checkpoint whose `at` is not canonical, so the
// string the chain hashes is always the string on the wire.
func (c *Checkpoint) UnmarshalJSON(data []byte) error {
	var w struct {
		At    string `json:"at"`
		Words int    `json:"words"`
		Chars int    `json:"chars"`
		Hash  string `json:"hash"`
	}
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	at, err := canonicalTimestamp(w.At)
	if err != nil {
		return fmt.Errorf("checkpoint: %w", err)
	}
	c.At, c.Words, c.Chars, c.Hash = at, w.Words, w.Chars, w.Hash
	return nil
}

// UnmarshalJSON refuses a bundle whose `generated` is not canonical, for
// the same reason: section 6 hashes it as a rendered string.
func (b *Bundle) UnmarshalJSON(data []byte) error {
	// A local type with no methods, so this does not recurse.
	type bundle Bundle
	var raw bundle
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var probe struct {
		Generated string `json:"generated"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return err
	}
	if _, err := canonicalTimestamp(probe.Generated); err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	*b = Bundle(raw)
	return nil
}
