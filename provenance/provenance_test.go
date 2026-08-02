// SPDX-License-Identifier: Apache-2.0

package provenance

import (
	"testing"
	"time"
)

func TestAppendChainsAndVerifies(t *testing.T) {
	var evs []Event
	for i := 0; i < 4; i++ {
		ev := Append(PrevHash(evs), Event{
			Kind: KindAIWrite,
			At:   time.Date(2026, 7, 20, 12, i, 0, 0, time.UTC),
			Span: Span{From: i, To: i + 3, Text: "abc"},
		})
		if ev.ID == "" || len(ev.Hash) != 64 {
			t.Fatalf("event %d not completed: %+v", i, ev)
		}
		evs = append(evs, ev)
	}
	if err := VerifyChain(evs); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

func TestVerifyChainDetectsEdit(t *testing.T) {
	evs := []Event{Append("", Event{Kind: KindAIWrite, Span: Span{From: 0, To: 2, Text: "hi"}})}
	evs = append(evs, Append(PrevHash(evs), Event{Kind: KindRemove, TargetID: evs[0].ID}))
	evs[0].Span.Text = "ho"
	if err := VerifyChain(evs); err == nil {
		t.Fatal("expected a chain break after editing an event")
	}
}

func TestVerifyChainDetectsReorder(t *testing.T) {
	a := Append("", Event{Kind: KindAIWrite, Span: Span{From: 0, To: 2, Text: "hi"}})
	b := Append(a.Hash, Event{Kind: KindHumanEdit, TargetID: a.ID})
	if err := VerifyChain([]Event{b, a}); err == nil {
		t.Fatal("expected a chain break after reordering")
	}
}

func TestDigestIsStable(t *testing.T) {
	ev := Event{
		ID:   "abc123",
		Kind: KindAIWrite,
		At:   time.Date(2026, 7, 20, 14, 3, 0, 0, time.UTC),
		Span: Span{From: 10, To: 20, Text: "written with an AI"},
	}
	// Pinned so a change to the chain encoding cannot pass unnoticed.
	const want = "8d04ee6cabf8c52da9a88391523a3fd020ba53d69fc9f47e99240eceaa2bfdfc"
	if got := Digest("", ev); got != want {
		t.Fatalf("digest changed: got %s want %s", got, want)
	}
	got := Digest("", ev)
	// The chain value must depend on prev.
	if Digest("ff", ev) == got {
		t.Fatal("digest ignores the previous chain value")
	}
}

func TestVerifyChainEmpty(t *testing.T) {
	if err := VerifyChain(nil); err != nil {
		t.Fatalf("empty chain should verify: %v", err)
	}
}
