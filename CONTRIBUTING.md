# Contributing

This is the trust core behind Folio. Changes here can affect whether a
receipt verifies, so the bar is high and deliberate.

## Before you start

- For anything that touches the bundle format, the signing digest or the
  timeline chain, open an issue first. A change to those is a format
  change, and format changes carry a new schema string rather than
  redefining version 1.
- For a verifier bug, a documentation fix or a build change, a pull
  request on its own is fine.

## Ground rules

- Both implementations, the Go module and the TypeScript verifier, must
  follow `SPEC.md` exactly on the signing digest, the timeline chain and
  the credential canonicalization. The Go suite signs a bundle and runs
  the verifier's tests against it, so a change that breaks the format
  fails a test in both languages.
- The Go module depends on the standard library only, reads no files and
  opens no network connections. Storage, keys and configuration belong
  to whatever program uses it.
- Do not add a network call to the verification path. The verifier
  checks a bundle with the bundle alone. That property is the point.
- The specification in `SPEC.md` is normative prose. If you change
  behavior, change the specification in the same pull request so the two
  never disagree.
- Tests come with the change, not after it.

## Style

- No em-dashes, no Oxford commas in prose. Plain, direct English.
- TypeScript passes `npm run check`. Go passes `gofmt -l .` with no
  output and `go vet ./...` clean.
- Commits: imperative subject under 50 characters, no trailing period.
  One logical change per commit.

## Licensing of contributions

By contributing you agree that your contribution is licensed under the
Apache License 2.0, the license of this repository. If you contribute on
behalf of an employer, make sure you are entitled to.
