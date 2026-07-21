# Security policy

This repository holds a verification format and the code that checks it.
A defect here is a defect in a trust claim, so we treat reports
seriously and welcome scrutiny of the cryptography.

## Reporting a vulnerability

Please report privately first. Email **security@adastracomputing.com**
with enough detail to reproduce. If you use PGP, say so and we will
exchange keys. Do not open a public issue for a security defect until we
have had a chance to respond.

We aim to acknowledge a report within three working days and to agree a
disclosure timeline with you. We will credit you when the fix ships,
unless you ask us not to.

## What is in scope

- Any way to make the verifier accept a bundle that was altered after
  signing, including forged signatures, timeline-chain collisions or
  body-hash mismatches that pass.
- Any gap between this repository's specification and the reference
  implementations that lets a valid producer and a valid verifier
  disagree.
- Any way the client-side verifier could be made to leak the bundle it
  is checking, or to consult a network service during verification.

## What is not a vulnerability

- The format does not and cannot prove that a human, rather than an
  automated pipeline, wrote a piece. This is stated in the
  specification. A demonstration that a machine can produce a valid
  bundle is expected behavior, not a defect.
- Trust in the party that serves the verifier page is assumed. If you
  do not trust that party, host the verifier yourself. That is why it is
  open.

## Cryptographic notes for reviewers

- Signatures are Ed25519 over a SHA-256 digest of per-field SHA-256
  hashes, with a versioned domain-separation tag. The construction is in
  section 6 of `SPEC.md`.
- The signing digest and the timeline chain are defined in section 5 and
  section 6 of `SPEC.md`. The verifier implements them, and its test
  suite checks a genuine signed fixture. If you find an input where the
  verifier disagrees with the specification, we want to hear about it
  even if you cannot show an exploit.
