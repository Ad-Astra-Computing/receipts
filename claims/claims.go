// SPDX-License-Identifier: Apache-2.0

// Package claims holds a producer's model of a sourced factual claim: a
// marked excerpt, the source URL it cites, and the status of that
// source the last time it was checked.
//
// This is the producer side, not the wire format. The bundle's own
// claim type is receipts.ClaimRef, and the format is deliberately
// looser than this package: SPEC section 3.1 makes `status` free text
// with no enumeration. Nothing here is normative for anyone writing a
// verifier.
//
// The package is pure. Fetching a source, storing a ledger and
// scheduling re-checks are the producer's business; what lives here is
// the shape that travels, its validation, and a canonical digest for
// comparing two claims without comparing their volatile check state.
package claims

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Status of a claim's source verification.
//
// These four values are this PRODUCER's vocabulary, not the format's.
// SPEC section 3.1 makes `status` free text, defines no enumeration and
// forbids a verifier from inferring one, precisely so that a producer
// with a richer or poorer notion of checking can say what it means. A
// bundle carrying "stale" or "" or "verified-by-hand" is valid and a
// verifier must accept it.
//
// Validate below refuses anything outside this set because a producer
// may hold itself to a stricter rule than the format requires. Nothing
// here constrains what a receipt may contain.
type Status string

const (
	// StatusUnchecked: the source has never been fetched.
	StatusUnchecked Status = "unchecked"
	// StatusOK: the source was reachable and matched its cite-time hash.
	StatusOK Status = "ok"
	// StatusChanged: the source was reachable but its bytes differ from
	// what was cited.
	StatusChanged Status = "changed"
	// StatusUnreachable: the source could not be fetched.
	StatusUnreachable Status = "unreachable"
)

// Valid reports whether s is one of the four statuses THIS PACKAGE
// defines. The format defines none: see the Status doc comment.
func (s Status) Valid() bool {
	switch s {
	case StatusUnchecked, StatusOK, StatusChanged, StatusUnreachable:
		return true
	}
	return false
}

// Claim is one marked passage anchored to a source URL.
type Claim struct {
	ID             string    `json:"id"`
	Excerpt        string    `json:"excerpt"`
	SourceURL      string    `json:"source_url"`
	HashAtCite     string    `json:"hash_at_cite,omitempty"`
	LastCheckHash  string    `json:"last_check_hash,omitempty"`
	LastCheckAt    time.Time `json:"last_check_at,omitempty"`
	LastCheckError string    `json:"last_check_error,omitempty"`
	Status         Status    `json:"status"`
	AddedAt        time.Time `json:"added_at"`
}

// Ledger is the set of claims recorded for one document.
type Ledger struct {
	RelPath string    `json:"rel_path"`
	Updated time.Time `json:"updated"`
	Claims  []Claim   `json:"claims"`
}

// DigestTag is the domain separation tag for the claim digest.
const DigestTag = "folio.claims.digest.v1"

// Digest returns a stable identifier for the substance of a claim: its
// excerpt, its source URL and its status. Check timestamps and hashes
// are excluded, so re-checking a source does not change the digest.
//
// This digest is a local convenience for comparing and deduplicating
// claims. It is not part of the receipts bundle signature: a bundle
// binds each claim field directly, per SPEC.md section 6.
func Digest(c Claim) string {
	h := sha256.New()
	add := func(s string) {
		x := sha256.Sum256([]byte(s))
		h.Write(x[:])
	}
	add(DigestTag)
	add(c.Excerpt)
	add(c.SourceURL)
	add(string(c.Status))
	return hex.EncodeToString(h.Sum(nil))
}

// Validate reports whether a claim carries the fields the format
// requires: a non-empty excerpt, a non-empty source URL and a status
// this package defines.
func Validate(c Claim) error {
	if strings.TrimSpace(c.Excerpt) == "" {
		return errors.New("claims: empty excerpt")
	}
	if strings.TrimSpace(c.SourceURL) == "" {
		return errors.New("claims: empty source URL")
	}
	if !c.Status.Valid() {
		return fmt.Errorf("claims: unknown status %q", c.Status)
	}
	return nil
}
