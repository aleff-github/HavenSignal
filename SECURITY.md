# Security Policy for Development

This repository handles a class of data for which confidentiality failures may cause severe real-world harm.

## Non-negotiable development rules

- No production secrets in Git.
- No real sensitive reports in development fixtures.
- No reporter data in logs.
- No external telemetry from reporter-facing or operator-sensitive paths.
- No direct use of uploaded filenames as storage paths.
- No direct serving of uploaded files from a public webroot.
- No direct browser opening of original PDF/image objects for normal operator review.
- No cryptographic key storage in the same data store as encrypted report objects unless an approved design explicitly establishes equivalent separation.
- No security-sensitive fallback to plaintext or weaker encryption.
- No "temporary" debug logging of secrets.
- No disabling CSRF, security headers, or authentication controls to make tests pass.
- No security-sensitive endpoint without negative/abuse tests.

## Vulnerability handling

Security bugs affecting confidentiality, authorization, cryptographic deletion, recovery credentials, audit integrity, file processing, or operator session controls are release blockers.

## Testing data

Use synthetic, non-identifying content only.
