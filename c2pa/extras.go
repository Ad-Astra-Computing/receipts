// SPDX-License-Identifier: Apache-2.0

package c2pa

import (
	"encoding/json"
	"errors"
	"fmt"
)

// The credential's signature covers every member of the object it was
// computed over, including members this package does not model. So
// parsing must not lose any of them, at any depth: a dropped member
// means the digest is taken over a smaller object than the one that was
// signed, and a verifier that keeps it (the browser canonicalizes
// exactly what it parsed) computes a different digest for the same
// credential.
//
// Each nested type therefore keeps whatever it did not recognise and
// puts it back when marshaling. Modelled fields always win, so an edit
// through the struct is never masked by a stale copy in extras.

// splitExtras decodes data into typed (via the caller's alias type) and
// returns the members that are not in known.
func splitExtras(data []byte, known map[string]bool) (map[string]json.RawMessage, error) {
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, err
	}
	var extras map[string]json.RawMessage
	for name, raw := range all {
		if known[name] {
			continue
		}
		if extras == nil {
			extras = make(map[string]json.RawMessage, 1)
		}
		extras[name] = raw
	}
	return extras, nil
}

// mergeExtras re-attaches unknown members to an encoded object.
func mergeExtras(base []byte, extras map[string]json.RawMessage) ([]byte, error) {
	if len(extras) == 0 {
		return base, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(base, &obj); err != nil {
		return nil, err
	}
	for name, raw := range extras {
		if _, taken := obj[name]; taken {
			continue
		}
		obj[name] = raw
	}
	return json.Marshal(obj)
}

// rejectNulls refuses members present with a literal null. A pointer
// field cannot tell null from absent, so preserving the distinction is
// impossible; the format refuses null instead (SPEC 3.1).
func rejectNulls(data []byte, names ...string) error {
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

var assetMembers = map[string]bool{"sha256": true, "size": true, "mime": true, "title": true, "url": true}

func (a *Asset) UnmarshalJSON(data []byte) error {
	type asset Asset
	var raw asset
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	// Presence matters: a missing size decoded to zero and then verified
	// as though it had been signed that way, and re-marshalled as an
	// explicit 0, which is a different object from the one that was
	// signed. SPEC 7.0 requires the member.
	var probe struct {
		Size *int64 `json:"size"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return err
	}
	if probe.Size == nil {
		return errors.New("c2pa: asset.size is missing")
	}
	if err := rejectNulls(data, "sha256", "size", "mime", "title", "url"); err != nil {
		return fmt.Errorf("c2pa: asset: %w", err)
	}
	extras, err := splitExtras(data, assetMembers)
	if err != nil {
		return err
	}
	*a = Asset(raw)
	a.extras = extras
	return nil
}

func (a Asset) MarshalJSON() ([]byte, error) {
	type asset Asset
	base, err := json.Marshal(asset(a))
	if err != nil {
		return nil, err
	}
	return mergeExtras(base, a.extras)
}

var generatorMembers = map[string]bool{"name": true, "version": true, "url": true}

func (g *GeneratorInfo) UnmarshalJSON(data []byte) error {
	type generator GeneratorInfo
	var raw generator
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if err := rejectNulls(data, "name", "version", "url"); err != nil {
		return fmt.Errorf("c2pa: claim_generator_info: %w", err)
	}
	extras, err := splitExtras(data, generatorMembers)
	if err != nil {
		return err
	}
	*g = GeneratorInfo(raw)
	g.extras = extras
	return nil
}

func (g GeneratorInfo) MarshalJSON() ([]byte, error) {
	type generator GeneratorInfo
	base, err := json.Marshal(generator(g))
	if err != nil {
		return nil, err
	}
	return mergeExtras(base, g.extras)
}

var signatureMembers = map[string]bool{"alg": true, "public_key": true, "value": true}

func (s *Signature) UnmarshalJSON(data []byte) error {
	type signature Signature
	var raw signature
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	extras, err := splitExtras(data, signatureMembers)
	if err != nil {
		return err
	}
	*s = Signature(raw)
	s.extras = extras
	return nil
}

func (s Signature) MarshalJSON() ([]byte, error) {
	type signature Signature
	base, err := json.Marshal(signature(s))
	if err != nil {
		return nil, err
	}
	return mergeExtras(base, s.extras)
}

var assertionMembers = map[string]bool{"label": true, "data": true}

func (a *Assertion) UnmarshalJSON(data []byte) error {
	type assertion Assertion
	var raw assertion
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	// `data` is required (SPEC 7.0) and its value may legitimately be
	// null, which a pointer cannot express: encoding/json sets a
	// *json.RawMessage to nil for null, making it indistinguishable from
	// absent. Presence is therefore checked on the raw object and the
	// value kept verbatim.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return err
	}
	if _, ok := probe["data"]; !ok {
		return errors.New("c2pa: assertion has no data")
	}
	extras, err := splitExtras(data, assertionMembers)
	if err != nil {
		return err
	}
	*a = Assertion(raw)
	a.Data = probe["data"]
	a.extras = extras
	return nil
}

func (a Assertion) MarshalJSON() ([]byte, error) {
	type assertion Assertion
	base, err := json.Marshal(assertion(a))
	if err != nil {
		return nil, err
	}
	return mergeExtras(base, a.extras)
}
