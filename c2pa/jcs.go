// SPDX-License-Identifier: Apache-2.0

package c2pa

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// This file implements the subset of RFC 8785 (JSON Canonicalization
// Scheme) that a content credential uses: objects with string keys
// sorted by UTF-16 code-unit order, arrays in their given order,
// strings with standard JSON escaping and no Unicode normalization,
// numbers as the safe integers the credential carries, plus booleans
// and null. It mirrors the reference implementation in
// verifier/src/jcs.ts line for line, because the two must agree on
// every byte for a Go-signed credential to verify in a browser.

// decodeJSON parses a JSON object, keeping numbers in their literal
// form so no float round trip can perturb a value on the way to the
// canonical serialization.
func decodeJSON(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("jcs: %w", err)
	}
	return v, nil
}

// canonicalValue returns the JCS serialization of an already-decoded
// JSON value.
func canonicalValue(v any) (string, error) {
	var sb strings.Builder
	if err := canonicalize(&sb, v); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// canonicalJSON parses raw JSON and returns its JCS serialization.
func canonicalJSON(raw []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", fmt.Errorf("jcs: %w", err)
	}
	return canonicalValue(v)
}

func canonicalize(sb *strings.Builder, v any) error {
	switch x := v.(type) {
	case nil:
		sb.WriteString("null")
		return nil
	case bool:
		if x {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
		return nil
	case string:
		return encodeString(sb, x)
	case json.Number:
		return encodeNumber(sb, x)
	case float64:
		return encodeNumber(sb, json.Number(strconv.FormatFloat(x, 'f', -1, 64)))
	case []any:
		sb.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := canonicalize(sb, item); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
		return nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sortUTF16(keys)
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := encodeString(sb, k); err != nil {
				return err
			}
			sb.WriteByte(':')
			if err := canonicalize(sb, x[k]); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
		return nil
	default:
		return fmt.Errorf("jcs: unsupported type %T", v)
	}
}

// sortUTF16 orders keys by UTF-16 code-unit sequence, which is what
// RFC 8785 mandates and what JavaScript's default string comparison
// gives the reference implementation for free.
func sortUTF16(keys []string) {
	encoded := make(map[string][]uint16, len(keys))
	for _, k := range keys {
		encoded[k] = utf16.Encode([]rune(k))
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := encoded[keys[i]], encoded[keys[j]]
		for n := 0; n < len(a) && n < len(b); n++ {
			if a[n] != b[n] {
				return a[n] < b[n]
			}
		}
		return len(a) < len(b)
	})
}

// encodeNumber writes the JSON number form. The credential carries only
// safe integers (sizes, counts, offsets), which JCS renders in plain
// decimal with no leading zeros and no plus sign. Anything else is
// rejected rather than guessed at, so a producer can never emit a
// number the browser verifier would serialize differently.
func encodeNumber(sb *strings.Builder, n json.Number) error {
	s := n.String()
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		if i > 1<<53-1 || i < -(1<<53-1) {
			return errors.New("jcs: integer outside the safe range")
		}
		sb.WriteString(strconv.FormatInt(i, 10))
		return nil
	}
	f, err := n.Float64()
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return fmt.Errorf("jcs: unrepresentable number %q", s)
	}
	if f == math.Trunc(f) && math.Abs(f) <= 1<<53-1 {
		sb.WriteString(strconv.FormatInt(int64(f), 10))
		return nil
	}
	return fmt.Errorf("jcs: non-integer number %q", s)
}

// encodeString writes the JSON string form JavaScript's JSON.stringify
// produces: the two-character escapes, control characters below U+0020
// as \u00xx, and every other character literal in UTF-8 with no
// Unicode normalization. Characters outside the basic multilingual
// plane stay literal, as a well-formed JSON.stringify leaves them.
func encodeString(sb *strings.Builder, s string) error {
	sb.WriteByte('"')
	for _, r := range replaceInvalid(s) {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\b':
			sb.WriteString(`\b`)
		case '\f':
			sb.WriteString(`\f`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(sb, `\u%04x`, r)
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
	return nil
}

// replaceInvalid substitutes U+FFFD for malformed UTF-8, matching what
// a JSON parser hands the reference implementation for the same bytes.
func replaceInvalid(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, string(utf8.RuneError))
}
