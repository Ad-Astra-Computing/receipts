// SPDX-License-Identifier: Apache-2.0

package receipts

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

// DigestTimeline builds the timeline digest for a run of checkpoints,
// normalizing every timestamp to whole UTC seconds so the RFC 3339
// rendering is exact and a browser reproduces the chain byte for byte.
// The input checkpoints carry no draft text: a producer digests its
// drafts before calling this.
func DigestTimeline(cps []Checkpoint) TimelineDigest {
	d := TimelineDigest{Checkpoints: make([]Checkpoint, 0, len(cps))}
	prev := ""
	for _, cp := range cps {
		cp.At = cp.At.UTC().Truncate(time.Second)
		d.Checkpoints = append(d.Checkpoints, cp)
		prev = ChainCheckpoint(prev, cp)
	}
	d.ChainHash = prev
	return d
}

// ChainCheckpoint binds every checkpoint field into the running chain,
// per SPEC.md section 5:
//
//	chain = SHA-256-hex( prev + "|" + at + "|" + words + "|" + chars + "|" + hash )
//
// The field order and the "|" separator are part of the format.
func ChainCheckpoint(prev string, cp Checkpoint) string {
	line := prev + "|" + cp.At.UTC().Format(time.RFC3339) +
		"|" + strconv.Itoa(cp.Words) + "|" + strconv.Itoa(cp.Chars) + "|" + cp.Hash
	sum := sha256.Sum256([]byte(line))
	return hex.EncodeToString(sum[:])
}

// VerifyTimeline recomputes the chain over t.Checkpoints and reports
// whether it matches t.ChainHash.
func VerifyTimeline(t TimelineDigest) bool {
	prev := ""
	for _, cp := range t.Checkpoints {
		prev = ChainCheckpoint(prev, cp)
	}
	return prev == t.ChainHash
}
