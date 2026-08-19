// SPDX-License-Identifier: Apache-2.0

// Command gen emits a signed receipts bundle fixture, and the body it
// describes, for the browser verifier's interop test:
//
//	go run ./verifier/gen > verifier/src/testdata/sample-bundle.json
//
// Everything is assembled in memory with the public module, so the
// fixture is exactly what a third-party producer would emit. A fresh
// demo keypair is generated on each run and the bundle carries its own
// public key, so the fixture is self-verifying and is not a claim
// about a real author.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Ad-Astra-Computing/receipts/c2pa"
	"github.com/Ad-Astra-Computing/receipts/history"
	"github.com/Ad-Astra-Computing/receipts/provenance"
	"github.com/Ad-Astra-Computing/receipts/receipts"
)

const body = "+++\ntitle = \"Keep the receipts\"\n+++\n\n" +
	"When anyone can generate text, a clean draft proves nothing. What still counts is the " +
	"work behind it: the sources checked, the lines cut, and the parts written with an AI " +
	"assistant, disclosed and signed. This note is one of them, so you can see how it was made.\n"

const (
	title = "Keep the receipts"
	url   = "https://blog.example.com/post/keep-the-receipts/"
)

func main() {
	out := flag.String("o", "", "write the fixture to this file instead of stdout")
	flag.Parse()

	bundle, err := build()
	if err != nil {
		fatal(err.Error())
	}
	if err := receipts.VerifyBody(bundle, []byte(body)); err != nil {
		fatal("self-verify failed: " + err.Error())
	}

	w := os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			fatal(err.Error())
		}
		defer f.Close()
		w = f
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(map[string]any{"bundle": bundle, "body": body}); err != nil {
		fatal(err.Error())
	}
}

// build assembles the fixture the way a producer would: measure the
// composition, disclose one AI-written phrase, digest the timeline,
// sign the credential and sign the bundle with the same key.
func build() (receipts.Bundle, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return receipts.Bundle{}, err
	}
	sum := sha256.Sum256([]byte(body))
	assetHash := hex.EncodeToString(sum[:])
	created := time.Now().UTC().Truncate(time.Second)

	// A few composition checkpoints, as a real draft would grow.
	start := created.Add(-90 * time.Minute)
	drafts := []string{
		"When anyone can generate text, a clean draft proves nothing.",
		"When anyone can generate text, a clean draft proves nothing. What still counts is the work behind it: the sources checked, the lines cut.",
		"When anyone can generate text, a clean draft proves nothing. What still counts is the work behind it: the sources checked, the lines cut, and the parts written with an AI assistant, disclosed and signed. This note is one of them, so you can see how it was made.",
	}
	snaps := make([]history.Snapshot, 0, len(drafts))
	for i, d := range drafts {
		snaps = append(snaps, history.NewSnapshot(start.Add(time.Duration(i)*20*time.Minute), d))
	}

	// One disclosed AI-written phrase, recorded on the provenance chain.
	const phrase = "written with an AI"
	from := strings.Index(body, phrase)
	if from < 0 {
		from = 0
	}
	ev := provenance.Append("", provenance.Event{
		Kind:  provenance.KindAIWrite,
		At:    created.Add(-30 * time.Minute),
		Model: "claude-opus-4-8",
		Span:  provenance.Span{From: from, To: from + len(phrase), Text: phrase},
	})
	if err := provenance.VerifyChain([]provenance.Event{ev}); err != nil {
		return receipts.Bundle{}, err
	}

	manifest, err := c2pa.Build(c2pa.BuildInput{
		Asset: c2pa.Asset{
			SHA256: assetHash,
			Size:   int64(len(body)),
			MIME:   "text/markdown",
			Title:  c2pa.Optional(title),
			URL:    c2pa.Optional(url),
		},
		Generator: c2pa.GeneratorInfo{
			Name:    "Folio",
			Version: c2pa.Optional("0.1.0"),
			URL:     c2pa.Optional("https://github.com/Ad-Astra-Computing/folio"),
		},
		CreatedAt: created,
		AIRanges: []c2pa.AIRange{{
			From:    ev.Span.From,
			To:      ev.Span.To,
			Model:   ev.Model,
			EventID: ev.ID,
			Hash:    ev.Hash,
			When:    ev.At.UTC().Format(time.RFC3339),
		}},
		ChainLen: 1,
	})
	if err != nil {
		return receipts.Bundle{}, err
	}
	cred, err := c2pa.Sign(manifest, key)
	if err != nil {
		return receipts.Bundle{}, err
	}

	bundle := receipts.Bundle{
		Schema:     receipts.Schema,
		Generated:  created,
		Post:       receipts.PostRef{Title: title, URL: url, SHA256: assetHash},
		Credential: cred,
		AIRanges: []receipts.AIRange{{
			From:  ev.Span.From,
			To:    ev.Span.To,
			Model: ev.Model,
			When:  ev.At.UTC().Format(time.RFC3339),
		}},
		Claims: []receipts.ClaimRef{{
			Excerpt:   "the sources checked, the lines cut",
			SourceURL: "https://example.com/how-this-was-made",
			Status:    "ok",
		}},
		Timeline: history.DigestTimeline(snaps),
	}
	return receipts.Sign(bundle, key)
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "gen:", msg)
	os.Exit(1)
}
