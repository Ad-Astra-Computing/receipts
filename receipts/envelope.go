// SPDX-License-Identifier: Apache-2.0

package receipts

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Decode reads a receipts file, which SPEC section 3a allows in two
// forms: a bare bundle, or a transport envelope carrying the published
// body alongside it.
//
// Bundle's own decoder cannot accept the envelope: it refuses unknown
// members, so `bundle` and `body` look to it exactly like the unsigned
// content it exists to reject. That is correct for a bundle and wrong
// for a file, and the distinction needs a function rather than a
// loosened rule, or every bundle would be able to carry two extra
// unsigned members.
//
// body is nil when the file carried no body. A caller MUST NOT treat
// that as a passed body check: it means nothing was compared.
func Decode(data []byte) (Bundle, []byte, error) {
	// Checked on the bytes, before parsing destroys the evidence:
	// duplicate members and lone surrogates (see jsontext.go).
	if err := validateJSONText(data); err != nil {
		return Bundle{}, nil, err
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return Bundle{}, nil, fmt.Errorf("receipts: not a JSON object: %w", err)
	}

	raw, isEnvelope := probe["bundle"]
	if !isEnvelope {
		var b Bundle
		if err := json.Unmarshal(data, &b); err != nil {
			return Bundle{}, nil, err
		}
		return b, nil, nil
	}

	// An envelope holds exactly these two members. Anything else is a
	// document pretending to be one.
	for name := range probe {
		if name != "bundle" && name != "body" {
			return Bundle{}, nil, fmt.Errorf("receipts: envelope has an unexpected member %q", name)
		}
	}
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return Bundle{}, nil, err
	}
	if rawBody, ok := probe["body"]; ok {
		var body string
		if err := json.Unmarshal(rawBody, &body); err != nil {
			return Bundle{}, nil, errors.New("receipts: envelope body is not a string")
		}
		return b, []byte(body), nil
	}
	return b, nil, nil
}

// VerifyFile decodes a receipts file and verifies it, checking the
// published body when the file carried one. bodyChecked reports whether
// it did, because "the text matches" and "there was no text" are
// different answers and only one of them is about the writing.
func VerifyFile(data []byte) (b Bundle, bodyChecked bool, err error) {
	b, body, err := Decode(data)
	if err != nil {
		return Bundle{}, false, err
	}
	if body == nil {
		return b, false, Verify(b)
	}
	return b, true, VerifyBody(b, body)
}
