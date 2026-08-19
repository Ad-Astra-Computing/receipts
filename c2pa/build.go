// SPDX-License-Identifier: Apache-2.0

package c2pa

import (
	"encoding/json"
	"time"
)

// ContextURI is the C2PA manifest context the credential declares.
const ContextURI = "https://c2pa.org/ns/manifest/1.4"

// ManifestType is the credential type.
const ManifestType = "ContentCredential"

// AIRange is one disclosed AI-authored span, as the folio.ai_ranges
// assertion carries it: the span, the model, and the provenance event
// that recorded it.
type AIRange struct {
	From    int    `json:"from"`
	To      int    `json:"to"`
	Model   string `json:"model"`
	EventID string `json:"event_id"`
	Hash    string `json:"hash"`
	When    string `json:"when"`
}

// BuildInput carries everything Build needs. The caller has already
// read the body, hashed it and resolved its metadata: this package
// opens no files and consults no configuration.
type BuildInput struct {
	// Asset identifies the published body.
	Asset Asset
	// Generator describes the producing tool. Build stamps
	// claim_generator as "<Name>/<Version>".
	Generator GeneratorInfo
	// CreatedAt is the credential timestamp. Zero means now. It is
	// truncated to whole UTC seconds so its RFC 3339 form is exact.
	CreatedAt time.Time
	// AIRanges are the disclosed spans. An empty slice omits the
	// folio.ai_ranges assertion entirely.
	AIRanges []AIRange
	// ChainLen is the length of the provenance chain the ranges came
	// from, recorded alongside them.
	ChainLen int
	// Mining sets the c2pa.training-mining entries. Nil selects
	// DefaultMining, which withholds every use.
	Mining map[string]string
}

// DefaultMining is the protective default for the c2pa.training-mining
// assertion: no training, no generative training, no inference, no
// data mining.
func DefaultMining() map[string]string {
	return map[string]string{
		"c2pa.ai_training":            "notAllowed",
		"c2pa.ai_generative_training": "notAllowed",
		"c2pa.ai_inference":           "notAllowed",
		"c2pa.data_mining":            "notAllowed",
	}
}

// Build assembles the unsigned manifest from in. It is deterministic:
// the same input always produces the same manifest, so signing it
// twice produces the same bytes.
func Build(in BuildInput) (Manifest, error) {
	created := in.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	created = created.UTC().Truncate(time.Second)

	mining := in.Mining
	if mining == nil {
		mining = DefaultMining()
	}

	m := Manifest{
		Context:        ContextURI,
		Type:           ManifestType,
		Asset:          in.Asset,
		ClaimGenerator: in.Generator.Name + "/" + strValue(in.Generator.Version),
		GeneratorInfo:  in.Generator,
		CreatedAt:      created,
		Assertions:     []Assertion{},
	}

	entries := make(map[string]map[string]string, len(mining))
	for k, v := range mining {
		entries[k] = map[string]string{"use": v}
	}
	miningData, err := json.Marshal(map[string]any{"entries": entries})
	if err != nil {
		return Manifest{}, err
	}
	m.Assertions = append(m.Assertions, Assertion{
		Label: "c2pa.training-mining",
		Data:  raw(miningData),
	})

	if len(in.AIRanges) > 0 {
		rangesData, err := json.Marshal(map[string]any{
			"ranges":    in.AIRanges,
			"chain_len": in.ChainLen,
		})
		if err != nil {
			return Manifest{}, err
		}
		m.Assertions = append(m.Assertions, Assertion{
			Label: "folio.ai_ranges",
			Data:  raw(rangesData),
		})
	}

	actionsData, err := json.Marshal(map[string]any{
		"actions": []map[string]string{
			{"action": "c2pa.created", "when": created.Format(time.RFC3339)},
		},
	})
	if err != nil {
		return Manifest{}, err
	}
	m.Assertions = append(m.Assertions, Assertion{
		Label: "c2pa.actions",
		Data:  raw(actionsData),
	})

	return m, nil
}

// raw wraps encoded JSON as an optional assertion payload.
func raw(b []byte) *json.RawMessage {
	m := json.RawMessage(b)
	return &m
}

// strValue reads an optional string, treating absence as empty.
func strValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// optional returns a pointer to s, or nil when s is empty, for the
// credential fields whose presence is part of the signed object.
func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
