// SPDX-License-Identifier: Apache-2.0

package receipts

import "testing"

func TestRejectsDuplicateMembers(t *testing.T) {
	for name, body := range map[string]string{
		"at the top level": `{"schema":"a","schema":"b"}`,
		"nested in object": `{"post":{"title":"a","title":"b"}}`,
		"inside an array":  `{"claims":[{"excerpt":"a","excerpt":"b"}]}`,
		"deep":             `{"a":{"b":{"c":1,"c":2}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateJSONText([]byte(body)); err == nil {
				t.Fatal("accepted a duplicate member")
			}
		})
	}
}

func TestAcceptsTheSameNameInDifferentObjects(t *testing.T) {
	// The same name in sibling objects is ordinary, not a duplicate.
	for name, body := range map[string]string{
		"siblings in an array": `{"claims":[{"excerpt":"a"},{"excerpt":"b"}]}`,
		"different objects":    `{"post":{"title":"a"},"credential":{"title":"b"}}`,
		"nested same name":     `{"a":{"a":{"a":1}}}`,
		"array of scalars":     `{"xs":[1,2,3],"ys":["a","a","a"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateJSONText([]byte(body)); err != nil {
				t.Fatalf("rejected a valid document: %v", err)
			}
		})
	}
}

func TestRejectsLoneSurrogates(t *testing.T) {
	for name, body := range map[string]string{
		"lone high":            `{"title":"\uD800"}`,
		"lone low":             `{"title":"\uDC00"}`,
		"high then plain text": `{"title":"\uD800abc"}`,
		"high then high":       `{"title":"\uD800\uD800"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateJSONText([]byte(body)); err == nil {
				t.Fatal("accepted a lone surrogate escape")
			}
		})
	}
}

func TestAcceptsWellFormedEscapes(t *testing.T) {
	for name, body := range map[string]string{
		"a real pair":       `{"title":"🧵"}`,
		"ordinary escape":   `{"title":"café"}`,
		"escaped backslash": `{"title":"not an escape: \\u0041"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateJSONText([]byte(body)); err != nil {
				t.Fatalf("rejected a valid document: %v", err)
			}
		})
	}
}

func TestAcceptsEscapedSurrogatePair(t *testing.T) {
	// 🧵 is the escaped form of the thread emoji: a valid pair.
	if err := validateJSONText([]byte(`{"title":"🧵"}`)); err != nil {
		t.Fatalf("rejected a valid surrogate pair: %v", err)
	}
	// Two pairs in a row, to prove the scanner resumes correctly.
	if err := validateJSONText([]byte(`{"t":"🧵🧵"}`)); err != nil {
		t.Fatalf("rejected two valid pairs: %v", err)
	}
	// A pair followed by a lone high surrogate is still a rejection.
	if err := validateJSONText([]byte(`{"t":"🧵\uD800"}`)); err == nil {
		t.Fatal("accepted a lone surrogate after a valid pair")
	}
}
