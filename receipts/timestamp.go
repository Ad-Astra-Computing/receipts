// SPDX-License-Identifier: Apache-2.0

package receipts

import (
	"bytes"
	"encoding/json"
	"errors"
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

// strictUnmarshal decodes into v and refuses any member the target type
// does not define.
//
// The signing digest (section 6) covers a fixed list of fields, so a
// member outside that list is carried but not signed. Accepting one
// would let a bundle hold content the signature says nothing about while
// the verifier reports that nothing was altered, which is the single
// claim this format makes. Forward compatibility belongs to a new schema
// string, where a verifier knows it is looking at something else, not to
// unsigned members of this one.
func strictUnmarshal(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

// rejectNullMembers refuses members present with a literal null value.
//
// Go decodes null into the zero value, so `"title": null` became "" and
// verified, while the TypeScript verifier refused it. Absent and null
// are different documents and section 3.1 gives every member a type;
// null is not a string.
func rejectNullMembers(data []byte, names ...string) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for _, name := range names {
		if v, ok := raw[name]; ok && string(v) == "null" {
			return fmt.Errorf("%s is null; omit it or give it a value", name)
		}
	}
	return nil
}

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
	// Pointers so a missing or null member is distinguishable from zero.
	// Without that, a checkpoint carrying no counts decoded to 0 and
	// verified, while the TypeScript verifier refused it as missing.
	var w struct {
		At    string  `json:"at"`
		Words *int    `json:"words"`
		Chars *int    `json:"chars"`
		Hash  *string `json:"hash"`
	}
	if err := strictUnmarshal(data, &w); err != nil {
		return err
	}
	at, err := canonicalTimestamp(w.At)
	if err != nil {
		return fmt.Errorf("checkpoint: %w", err)
	}
	if w.Words == nil || w.Chars == nil || w.Hash == nil {
		return errors.New("checkpoint: words, chars and hash are required")
	}
	c.At, c.Words, c.Chars, c.Hash = at, *w.Words, *w.Chars, *w.Hash
	return nil
}

// UnmarshalJSON refuses an ai_range whose `when` is not canonical. It is
// optional, but when present it is signed (section 6 hashes it as a
// rendered string), and the TypeScript verifier refuses non-canonical
// forms, so accepting one here would split the two implementations.
func (r *AIRange) UnmarshalJSON(data []byte) error {
	var w struct {
		From  *int    `json:"from"`
		To    *int    `json:"to"`
		Model string  `json:"model"`
		When  *string `json:"when"`
	}
	if err := strictUnmarshal(data, &w); err != nil {
		return err
	}
	if err := rejectNullMembers(data, "from", "to", "model", "when"); err != nil {
		return fmt.Errorf("ai_range: %w", err)
	}
	// A present-but-empty `when` is not the same as an absent one: the
	// empty string is not a timestamp, and the TypeScript verifier
	// refuses it, so accepting it here would split the two.
	if w.When != nil {
		if _, err := canonicalTimestamp(*w.When); err != nil {
			return fmt.Errorf("ai_range: %w", err)
		}
	}
	if w.From == nil || w.To == nil {
		return errors.New("ai_range: from and to are required")
	}
	r.From, r.To, r.Model = *w.From, *w.To, w.Model
	if w.When != nil {
		r.When = *w.When
	}
	return nil
}

// UnmarshalJSON refuses a bundle whose `generated` is not canonical, for
// the same reason: section 6 hashes it as a rendered string.
func (b *Bundle) UnmarshalJSON(data []byte) error {
	// A local type with no methods, so this does not recurse.
	type bundle Bundle
	var raw bundle
	if err := strictUnmarshal(data, &raw); err != nil {
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

// PostRef, TimelineDigest, ClaimRef and Signature decode strictly too:
// DisallowUnknownFields applies to the type being decoded, not to the
// types nested inside it, so without these an unsigned member could hide
// one level down.

func (p *PostRef) UnmarshalJSON(data []byte) error {
	type postRef PostRef
	var raw postRef
	if err := strictUnmarshal(data, &raw); err != nil {
		return fmt.Errorf("post: %w", err)
	}
	if err := rejectNullMembers(data, "title", "url", "sha256"); err != nil {
		return fmt.Errorf("post: %w", err)
	}
	*p = PostRef(raw)
	return nil
}

func (t *TimelineDigest) UnmarshalJSON(data []byte) error {
	type timeline TimelineDigest
	var raw timeline
	if err := strictUnmarshal(data, &raw); err != nil {
		return fmt.Errorf("timeline: %w", err)
	}
	// The member is required even when its value is the empty string,
	// which is the chain of no checkpoints (SPEC 3.1). Absent is not the
	// same as empty, and the TypeScript verifier refuses absent.
	var probe struct {
		ChainHash *string `json:"chain_hash"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return fmt.Errorf("timeline: %w", err)
	}
	if probe.ChainHash == nil {
		return errors.New("timeline: chain_hash is missing")
	}
	*t = TimelineDigest(raw)
	return nil
}

func (c *ClaimRef) UnmarshalJSON(data []byte) error {
	type claimRef ClaimRef
	var raw claimRef
	if err := strictUnmarshal(data, &raw); err != nil {
		return fmt.Errorf("claim: %w", err)
	}
	if err := rejectNullMembers(data, "excerpt", "source_url", "status"); err != nil {
		return fmt.Errorf("claim: %w", err)
	}
	*c = ClaimRef(raw)
	return nil
}

func (s *Signature) UnmarshalJSON(data []byte) error {
	type signature Signature
	var raw signature
	if err := strictUnmarshal(data, &raw); err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	if err := rejectNullMembers(data, "alg", "public_key", "value"); err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	*s = Signature(raw)
	return nil
}
