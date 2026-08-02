// SPDX-License-Identifier: Apache-2.0

package c2pa

import "testing"

// These vectors mirror verifier/src/jcs.test.ts one for one. The two
// canonicalizers have to agree on every byte, so they are tested
// against the same expectations in both languages.
func TestCanonicalJSONVectors(t *testing.T) {
	cases := []struct{ in, want string }{
		{`null`, `null`},
		{`true`, `true`},
		{`false`, `false`},
		{`0`, `0`},
		{`42`, `42`},
		{`-7`, `-7`},
		{`"hi"`, `"hi"`},
		{`""`, `""`},

		// Object keys sort by UTF-16 code-unit order.
		{`{"b":1,"a":2,"c":3}`, `{"a":2,"b":1,"c":3}`},
		{`{"a":1,"A":2}`, `{"A":2,"a":1}`},
		{`{"z":1,"1":2}`, `{"1":2,"z":1}`},

		// Array order is preserved and never sorted.
		{`[3,1,2]`, `[3,1,2]`},
		{`["b","a"]`, `["b","a"]`},
		{`[]`, `[]`},

		// Nesting sorts keys at every level.
		{
			`{"outer":{"z":[1,{"y":1,"x":2}],"a":"v"},"first":true}`,
			`{"first":true,"outer":{"a":"v","z":[1,{"x":2,"y":1}]}}`,
		},

		// String escaping: the mandatory short forms, control
		// characters as \u00xx, non-ASCII literal and unnormalized.
		{`"a\"b"`, `"a\"b"`},
		{`"a\\b"`, `"a\\b"`},
		{"\"line\\nfeed\"", `"line\nfeed"`},
		{"\"tab\\tend\"", `"tab\tend"`},
		{`"\u0001"`, `"\u0001"`},
		{`"é"`, "\"é\""},
		{`"é"`, "\"é\""},
		// Characters outside the basic multilingual plane stay literal.
		{`"🚀"`, "\"\U0001F680\""},

		// A credential-shaped fixture, matching the TypeScript vector.
		{
			`{"@context":"https://c2pa.org/ns/manifest/1.4","type":"ContentCredential",` +
				`"asset":{"sha256":"ab","size":3,"mime":"text/markdown"},` +
				`"signature":{"alg":"Ed25519","public_key":"k"}}`,
			`{"@context":"https://c2pa.org/ns/manifest/1.4",` +
				`"asset":{"mime":"text/markdown","sha256":"ab","size":3},` +
				`"signature":{"alg":"Ed25519","public_key":"k"},` +
				`"type":"ContentCredential"}`,
		},
	}
	for _, c := range cases {
		got, err := canonicalJSON([]byte(c.in))
		if err != nil {
			t.Fatalf("canonicalJSON(%s): %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("canonicalJSON(%s) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestCanonicalJSONRejectsUnsafeNumbers(t *testing.T) {
	for _, in := range []string{`9007199254740993`, `1.5`, `-2.25`} {
		if got, err := canonicalJSON([]byte(in)); err == nil {
			t.Fatalf("canonicalJSON(%s) = %s, want an error", in, got)
		}
	}
}

func TestCanonicalJSONRejectsMalformedInput(t *testing.T) {
	for _, in := range []string{``, `{`, `{"a":}`} {
		if _, err := canonicalJSON([]byte(in)); err == nil {
			t.Fatalf("canonicalJSON(%q) accepted malformed input", in)
		}
	}
}
