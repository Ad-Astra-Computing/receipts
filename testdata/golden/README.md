# Golden vectors

Signed bundles that freeze the wire format. The Go suite verifies them
with the same code path a third party would use
(`receipts/golden_test.go`), so a change to the signing digest, the
timeline chain or the credential canonicalization breaks these before it
can reach a published bundle.

They are **independent vectors, not copies**. Each was signed once, by a
throwaway key, and is never regenerated: that is the whole point, since a
vector regenerated from the current code cannot detect that the current
code changed. They therefore differ from the fixtures under `verifier/`
in key, timestamps and content, and are expected to.

- `sample-bundle.json`: a bundle with disclosed AI ranges and sourced
  claims, in the `{bundle, body}` transport envelope.
- `sample-hero.json`: a bundle with a longer timeline.

Related but different things, so it is worth naming them:

- `verifier/src/testdata/sample-bundle.json` is the interop fixture. The
  Go interop gate regenerates it and hands it to the TypeScript suite.
- `verifier/src/sample.receipts.json` is the demonstration receipt the
  hosted page loads.
- `testdata/rejections.json` is the shared rejection corpus: mutations
  both implementations must refuse.

If a change here is deliberate, it is a format change, and it needs a new
schema string rather than an edited vector.
