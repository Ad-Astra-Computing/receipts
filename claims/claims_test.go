// SPDX-License-Identifier: Apache-2.0

package claims

import (
	"testing"
	"time"
)

func sample() Claim {
	return Claim{
		ID:        "clm_abcdef",
		Excerpt:   "the sources checked",
		SourceURL: "https://example.com/source",
		Status:    StatusOK,
		AddedAt:   time.Date(2026, 7, 20, 13, 0, 0, 0, time.UTC),
	}
}

func TestValidate(t *testing.T) {
	if err := Validate(sample()); err != nil {
		t.Fatalf("valid claim rejected: %v", err)
	}
	cases := map[string]func(c *Claim){
		"empty excerpt":    func(c *Claim) { c.Excerpt = "  " },
		"empty source URL": func(c *Claim) { c.SourceURL = "" },
		"unknown status":   func(c *Claim) { c.Status = "maybe" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := sample()
			mutate(&c)
			if err := Validate(c); err == nil {
				t.Fatalf("expected %s to be rejected", name)
			}
		})
	}
}

func TestDigestIgnoresCheckState(t *testing.T) {
	a := sample()
	b := sample()
	b.LastCheckAt = time.Now()
	b.LastCheckHash = "deadbeef"
	b.HashAtCite = "cafebabe"
	b.ID = "clm_other"
	if Digest(a) != Digest(b) {
		t.Fatal("digest changed with volatile check state")
	}
}

func TestDigestCoversSubstance(t *testing.T) {
	base := Digest(sample())
	for name, mutate := range map[string]func(c *Claim){
		"excerpt": func(c *Claim) { c.Excerpt += "!" },
		"source":  func(c *Claim) { c.SourceURL += "?x=1" },
		"status":  func(c *Claim) { c.Status = StatusChanged },
	} {
		c := sample()
		mutate(&c)
		if Digest(c) == base {
			t.Fatalf("digest ignores the %s", name)
		}
	}
}

func TestStatusValid(t *testing.T) {
	for _, s := range []Status{StatusUnchecked, StatusOK, StatusChanged, StatusUnreachable} {
		if !s.Valid() {
			t.Fatalf("%q should be valid", s)
		}
	}
	if Status("").Valid() || Status("ok ").Valid() {
		t.Fatal("unknown statuses must not validate")
	}
}
