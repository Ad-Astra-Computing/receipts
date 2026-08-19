// SPDX-License-Identifier: Apache-2.0

package receipts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Two properties of a receipts file cannot be checked after parsing,
// because parsing destroys the evidence. Both are checked here, on the
// bytes as received.
//
// Duplicate member names: every JSON parser keeps one of the values and
// discards the other, and they do not all keep the same one. A document
// with a duplicate therefore means different things to different
// verifiers, and the signature covers only one of those meanings. There
// is no safe way to pick, so it is refused.
//
// Lone surrogates: a \uD800-\uDFFF escape with no partner is not a
// character. Go's decoder replaces it with U+FFFD, JavaScript keeps it,
// so the two canonicalize different strings and compute different
// digests for the same file. RFC 8785 requires rejection, and this is
// where it happens.
func validateJSONText(data []byte) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("receipts: the file is not valid UTF-8")
	}
	if err := rejectLoneSurrogates(data); err != nil {
		return err
	}
	if err := rejectNumberSpellings(data); err != nil {
		return err
	}
	return rejectDuplicateMembers(data)
}

// rejectNumberSpellings refuses a number written with a fractional part
// or an exponent. Every number in this format is an integer (SPEC
// section 4), and 1, 1.0 and 1e0 are one value with three spellings: a
// typed decoder refuses two of them and a browser parser cannot tell
// them apart, so the check belongs on the text. The browser does the
// same in verifier/src/jsontext.ts.
func rejectNumberSpellings(data []byte) error {
	s := string(data)
	inString := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inString {
			if c == '\\' {
				i++
			} else if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			continue
		}
		if c != '-' && (c < '0' || c > '9') {
			continue
		}
		j := i
		if s[j] == '-' {
			j++
		}
		start := j
		for j < len(s) && (s[j] == '.' || s[j] == 'e' || s[j] == 'E' || s[j] == '+' || s[j] == '-' || (s[j] >= '0' && s[j] <= '9')) {
			j++
		}
		token := s[start:j]
		if strings.ContainsAny(token, ".eE") {
			return fmt.Errorf("receipts: %s is written with a fractional part or an exponent; this format carries whole numbers only", s[i:j])
		}
		i = j - 1
	}
	return nil
}

func rejectLoneSurrogates(data []byte) error {
	s := string(data)
	for i := 0; i+5 < len(s); i++ {
		if s[i] != '\\' || s[i+1] != 'u' {
			continue
		}
		// A preceding backslash means this one is escaped, not an escape.
		backslashes := 0
		for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
			backslashes++
		}
		if backslashes%2 == 1 {
			continue
		}
		r, ok := parseHex4(s[i+2 : i+6])
		if !ok {
			continue // malformed escapes are the decoder's business
		}
		if !utf16.IsSurrogate(rune(r)) {
			continue
		}
		// A high surrogate is only valid immediately followed by a low one.
		if i+11 < len(s) && s[i+6] == '\\' && s[i+7] == 'u' {
			if r2, ok2 := parseHex4(s[i+8 : i+12]); ok2 {
				if utf16.DecodeRune(rune(r), rune(r2)) != 0xFFFD {
					i += 11 // consume the pair
					continue
				}
			}
		}
		return fmt.Errorf("receipts: the file contains a lone surrogate escape (\\u%04X), which is not a character", r)
	}
	return nil
}

// endValue records that a scalar value has been consumed: inside an
// object the next token is a member name again.
func endValue(stack []map[string]bool, path *[]string, expectKey *bool) {
	if len(stack) > 0 && stack[len(stack)-1] != nil {
		*expectKey = true
		if len(*path) > 0 {
			*path = (*path)[:len(*path)-1]
		}
	}
}

func parseHex4(s string) (int, bool) {
	if len(s) != 4 {
		return 0, false
	}
	n := 0
	for _, c := range s {
		n <<= 4
		switch {
		case c >= '0' && c <= '9':
			n |= int(c - '0')
		case c >= 'a' && c <= 'f':
			n |= int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			n |= int(c-'A') + 10
		default:
			return 0, false
		}
	}
	return n, true
}

// rejectDuplicateMembers walks the document and refuses any object that
// names the same member twice, at any depth.
func rejectDuplicateMembers(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	// One set of seen names per open object; nil marks an open array.
	var stack []map[string]bool
	var path []string
	expectKey := false

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err // malformed JSON: the decoder reports it properly
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, map[string]bool{})
				expectKey = true
			case '[':
				stack = append(stack, nil)
				expectKey = false
			case '}', ']':
				stack = stack[:len(stack)-1]
				if len(path) > 0 {
					path = path[:len(path)-1]
				}
				expectKey = len(stack) > 0 && stack[len(stack)-1] != nil
			}
		case string:
			if expectKey && len(stack) > 0 && stack[len(stack)-1] != nil {
				seen := stack[len(stack)-1]
				if seen[t] {
					where := strings.Join(path, ".")
					if where == "" {
						where = "the top level"
					}
					return fmt.Errorf("receipts: %q appears twice in %s; a duplicate member means different things to different parsers", t, where)
				}
				seen[t] = true
				path = append(path, t)
				expectKey = false
				continue
			}
			endValue(stack, &path, &expectKey)
		default:
			endValue(stack, &path, &expectKey)
		}
	}
}
