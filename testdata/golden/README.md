# Golden vectors

These files freeze the wire format. They are signed bundles that the
reference TypeScript verifier (`verifier/src/verify.ts`) accepts today,
so any change to the Go implementation that breaks one of them is a
change to the format itself.

- `sample-bundle.json` mirrors `verifier/src/testdata/sample-bundle.json`,
  the interop fixture: `{bundle, body}`.
- `sample-hero.json` mirrors `verifier/src/sample.receipts.json`, the
  sample the hosted verifier loads.

The Go test suite verifies both with the same code path a third party
would use, so the two implementations stay pinned to one format.
