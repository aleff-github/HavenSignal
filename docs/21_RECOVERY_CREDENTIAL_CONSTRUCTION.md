# 21 — Recovery Credential Encoding and Verifier Construction

## Status

**OWNER-APPROVED — project-owner decision recorded on 2026-08-25;
independent cryptographic review remains required.**

This approval records all five owner choices in this document. It does not
substitute for the independent cryptographic review required by
`SEC-RECOVERY-005` and does not authorize submission or recovery endpoints.
CAPTCHA, Response-DEK, Key Service, audit-receipt, deployment, and other
dependent gates remain independently blocking.

## Governing requirements

This owner-approved construction applies primarily to:

- `SEC-CONF-006..008`;
- `SEC-ANON-001..004`;
- `SEC-RECOVERY-001..005`;
- `SEC-RESPONSE-002..008`;
- `SEC-CAPTCHA-001..004`;
- `SEC-BROWSER-001..002`.

`docs/01_SECURITY_BASELINE.md` remains normative. A conflict stops
implementation and returns the decision to the project owner.

## Security outcome

Recovery uses two independent CSPRNG outputs:

| Value | Raw size | Canonical display encoding | Security role |
|---|---:|---|---|
| Ticket ID | 16 bytes / 128 bits | 26 uppercase unpadded RFC 4648 Base32 characters | Public, non-sequential lookup identifier |
| Recovery Secret | 32 bytes / 256 bits | 43 unpadded RFC 4648 base64url characters | Authentication secret |

The server persists the Ticket ID and a full 32-byte HMAC verifier. It never
persists or logs the Recovery Secret. Possession of the application database
alone is insufficient to test a candidate secret without the separately held
verification key, and the candidate secret retains 256 bits of random entropy.

The verifier only authorizes the separately approved recovery workflow. It is
not an encryption key, a Response-DEK, a session, a reporter account, or a
general report-reading capability.

## Trust boundaries

The construction crosses these boundaries:

- the Reporter Gateway generates the two raw values during the approved
  submission protocol and transiently sends them to the Recovery Verifier
  Service's create-only operation;
- the Recovery Verifier Service alone holds the raw HMAC key and returns only
  the version, key identifier, and verifier tag;
- the metadata store persists the public Ticket ID and verifier record, but no
  raw verification key or Recovery Secret;
- the Recovery Gateway accepts credentials only through POST and asks the
  Recovery Verifier Service for a boolean authorization result;
- the Key Service independently decides whether the one eligible Response-DEK
  may be used under current server-authoritative state and expiry.

The Reporter Gateway and Recovery Gateway do not receive the HMAC key. The
Recovery Verifier Service receives no Report-DEK, Response-DEK, report text,
attachment, Response Note, operator identity, audit-history mutation
capability, or general report-decryption operation.

Both service operations use an authenticated, encrypted, bounded channel with
body and credential fields excluded from proxy, application, audit, tracing,
and error logging. The create operation is bound to one current, unaccepted
submission attempt and cannot produce or replace verifier state for an
existing Ticket ID.

## Exact credential generation

### Random source

Each value is generated independently from the operating system's approved
cryptographic random source. The Python implementation candidate is
`secrets.token_bytes`, subject to production runtime and entropy-source
validation.

Generation must fail closed if the random source fails or returns the wrong
length. There is no timestamp, counter, database sequence, report digest,
reporter metadata, IP address, User-Agent, Ticket ID derivation, PRNG seed
fallback, or application-defined entropy mixing.

Ticket ID collisions are rejected by a database uniqueness constraint. A
collision retries fresh Ticket ID generation at most three times; a third
collision aborts the attempt with a controlled internal security event because
it indicates a random-source or implementation failure. The Recovery Secret is
not regenerated merely because the Ticket ID collided.

### Ticket ID encoding

The canonical Ticket ID is:

```text
BASE32_RFC4648(ticket_id_bytes), with all trailing "=" removed
```

It is exactly 26 ASCII characters in `[A-Z2-7]`. Whitespace, hyphens,
lowercase, padding, Unicode lookalikes, and every other character are rejected.
The decoder must:

1. enforce the exact ASCII alphabet and length before decoding;
2. restore only the mechanically required internal padding;
3. decode to exactly 16 bytes;
4. re-encode and require exact equality with the submitted text.

The re-encoding check rejects non-canonical pad bits and prevents multiple text
representations from identifying the same raw value.

### Recovery Secret encoding

The canonical Recovery Secret is:

```text
BASE64URL_RFC4648(recovery_secret_bytes), with all trailing "=" removed
```

It is exactly 43 case-sensitive ASCII characters in `[A-Za-z0-9_-]`.
Whitespace, padding, standard-base64 `+` and `/`, Unicode lookalikes, and every
other character are rejected. The decoder applies the same four strict steps
as the Ticket ID decoder and must produce exactly 32 bytes before exact
re-encoding comparison.

Neither decoder silently trims, case-folds, replaces characters, or accepts an
alternate alphabet. Parsing failures use the same external non-success class
as every other unsuccessful recovery attempt.

## Exact verifier construction

### Algorithm and key

Verifier version `1` uses full-length HMAC-SHA-256 as standardized by RFC 2104
and instantiated/tested by RFC 4231.

For each active key version, `K_recovery_verifier` is an independently
generated 32-byte key. It is purpose-separated from:

- Django `SECRET_KEY`;
- Report-DEKs and Response-DEKs;
- encryption, wrapping, audit, export, TLS, CAPTCHA, CSRF, session, and
  service-authentication keys.

The tag is not truncated.

### Canonical HMAC message

The exact HMAC input for version `1` is:

```text
ASCII("anonymous-reporting/recovery-verifier/v1")
|| 0x00
|| ticket_id_bytes[16]
|| recovery_secret_bytes[32]
```

The fixed domain label, terminating zero byte, algorithm version, and fixed
field lengths make the construction unambiguous and purpose-specific.

The persisted verifier record contains only:

```text
scheme_version = 1
verifier_key_id = server-controlled opaque key identifier
verifier_tag = HMAC-SHA-256(K_recovery_verifier[key_id], canonical_message)
```

The key identifier is selected by the service and cannot be supplied or
overridden by the reporter. Unknown versions, unknown key identifiers, wrong
field lengths, malformed encodings, service errors, and key unavailability all
fail closed.

### Verification

The Recovery Verifier Service recomputes the full 32-byte tag and compares it
with a constant-time primitive such as `hmac.compare_digest`. It never returns
the expected tag or any partial-match information.

A successful HMAC comparison is necessary but not sufficient for response
disclosure. The recovery workflow must also validate CAPTCHA and current
server-authoritative eligibility, then obtain a narrowly scoped Response-DEK
use authorization. Expired, destroyed, non-available, or otherwise ineligible
state remains denied even when credentials are correct.

Unknown-ticket handling must execute a bounded dummy-verification path using a
separate dummy key/record so that it does not skip the cryptographic work.
External status, template, headers, response class, and failure wording remain
generic. The implementation must test timing distributions and must not claim
perfect indistinguishability.

No per-ticket lockout, distinct error, redirect, or visible delay may reveal
whether a Ticket ID exists. Abuse controls are global and use the separately
approved self-hosted CAPTCHA without IP or device fingerprinting.

## Key lifecycle and rotation

- The raw verification keys exist only in the approved Recovery Verifier
  Service trust domain; they are absent from source code, Django settings,
  application databases, application logs, audit events, browser storage, and
  reporter-facing responses.
- One key version is active for creation. Retired versions may verify existing
  records but cannot create new records.
- A verifier record retains its server-selected key identifier; rotation never
  guesses a key, rewrites the tag from a submitted secret, or silently falls
  back to another version.
- A retired key may be destroyed only after no eligible recovery record refers
  to it and the approved restore tests prove that restored metadata cannot
  regain Response-DEK use.
- Compromise or loss triggers a separate reviewed rotation/incident procedure.
  Loss fails closed and may make affected responses unavailable; it never
  enables a plaintext or unkeyed fallback.
- Verifier-key backup is infrastructure-key material and requires its own
  approved encrypted access and recovery procedure. It must not confer report
  selection, Response-DEK use, or report-reading authority on the
  Infrastructure / Key Custodian.

The verifier key does not replace the Response-DEK non-resurrection rules.
After server-authoritative Response-DEK expiry or destruction, restoring an
old verifier record or verifier key must not make the response usable.

## Credential delivery and browser handling

The one explicit post-submission display follows the sequencing and
lost-response policy in `docs/20_SUBMISSION_ACCEPTANCE_PROTOCOL.md`. This
document does not independently approve that policy.

The credential response must use `Cache-Control: no-store`, `Pragma: no-cache`,
`Referrer-Policy: no-referrer`, the approved restrictive CSP, and no
third-party resources. The Recovery Secret is never put in a URL, cookie,
download, email, SMS, localStorage, IndexedDB, service worker, server-side
session, server-side draft, log, audit event, alert, trace, or error message.

No reload, retry, back navigation, administrator action, or recovery function
may cause the server to emit it again.

## Failure behavior

| Failure | Required behavior |
|---|---|
| Random source unavailable/wrong length | Abort before acceptance; no fallback generator |
| Repeated Ticket ID collision | Abort after three fresh-ID attempts; controlled alert/event without the ID |
| Encoding malformed/non-canonical | Generic non-success; no lookup or alternate decoder |
| Verifier service/key unavailable | Generic non-success; no local/unkeyed/plaintext fallback |
| Unknown version/key identifier | Generic non-success and controlled internal event |
| HMAC mismatch | Generic non-success; no partial-match detail |
| Correct credentials but response unavailable/expired/destroyed | Same generic non-success |
| Concurrent first reads | Exactly one immutable `first_read_at` and expiry; later valid reads reuse it |
| Response-DEK expired | Deny before use even while cleanup retries |
| Logging/telemetry attempts to include credentials | Reject/redact at the schema boundary and fail the security test |

## Persisted and prohibited data

| Data | Persisted form | Destruction/invalidation |
|---|---|---|
| Ticket ID | 16 raw bytes with uniqueness constraint | Removed with recovery state under approved lifecycle |
| Recovery Secret | Never persisted | Transient copies released as soon as verifier/display work completes |
| Verifier tag | Full 32-byte HMAC plus version/key ID | Invalidated/removed at response expiry or terminal destruction |
| Verifier key | Separate verifier-service key domain only | Versioned retirement after no eligible references and restore proof |
| Response-DEK | Approved Key Service live domain only | Destroyed under `SEC-RESPONSE-004..008` |

Logs, audit events, alerts, metrics, traces, exception strings, and support tools
must not contain the canonical credential text, decoded bytes, verifier tag,
raw HMAC message, or raw verifier key.

## Required tests before enablement

At minimum, tests must prove:

- exact raw sizes and canonical encoded lengths/alphabet;
- independent generation of Ticket ID and Recovery Secret;
- strict rejection of whitespace, lowercase Ticket IDs, padding, alternate
  alphabets, Unicode, wrong lengths, and non-canonical pad bits;
- RFC 4231 HMAC-SHA-256 conformance plus the application framing vector below;
- full-length constant-time tag comparison and no partial-match behavior;
- database uniqueness and collision retry/abort behavior;
- wrong Ticket ID, wrong secret, swapped fields, wrong version, wrong key ID,
  retired-key creation, and unavailable service all fail closed;
- unknown-ticket dummy verification and generic external responses;
- no credential, tag, key, body, or raw parsing error reaches logs, audit,
  alerts, tracing, URLs, cookies, or browser persistence;
- verifier success alone cannot use a Response-DEK;
- concurrent first reads establish one immutable server-time expiry;
- restored metadata/verifier keys cannot bypass Response-DEK expiry or
  destruction.

### Application framing test vector

```text
K_recovery_verifier = 000102030405060708090a0b0c0d0e0f
                      101112131415161718191a1b1c1d1e1f
ticket_id_bytes     = 202122232425262728292a2b2c2d2e2f
Ticket ID           = EAQSEIZEEUTCOKBJFIVSYLJOF4
recovery_secret     = 303132333435363738393a3b3c3d3e3f
                      404142434445464748494a4b4c4d4e4f
Recovery Secret     = MDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk8
expected HMAC tag   = c05bdf21866a92c9c0b74bdda3bc7ca6
                      f4e0a3e6c5f391c6fbc247fd1ac2945c
```

Test-vector material is public fixture data and must never be accepted as a
production key or credential.

## Recorded project-owner decision

On 2026-08-25 the project owner approved:

1. 128-bit Ticket IDs encoded as strict, uppercase, unpadded RFC 4648 Base32;
2. 256-bit Recovery Secrets encoded as strict, unpadded RFC 4648 base64url;
3. version-1 full HMAC-SHA-256 over the exact domain-separated fixed-length
   message in this document;
4. a distinct Recovery Verifier Service holding versioned 32-byte keys, with
   create-only and boolean-verify capabilities and constant-time comparison;
5. fail-closed three-attempt Ticket ID collision handling and the documented
   rotation, dummy-verification, persistence, and destruction rules.

Independent cryptographic review remains a release gate even after owner
approval. Endpoint implementation also remains blocked by all dependent OPEN
decisions.

## Stage A inert implementation evidence

The current implementation may validate only the canonical text shape of public
Ticket IDs and Recovery Secrets and return content-free shape descriptors. It
must not return or persist supplied credential text, decoded bytes, verifier
tags, verifier keys, or raw HMAC messages.

The Stage A descriptor and its non-executing source policy provide review
evidence for exact sizes, encodings, domain label, tag size, generic rejection,
and absence of generation, HMAC/verifier computation, storage, lookup, endpoint,
service-call, and authorization behavior. They do not implement or approve
credential generation, verifier creation or verification, recovery lookup,
Response-DEK use, persistence, deployment, or production recovery.

The recovery failure behavior profile is also represented by inert descriptors
and a non-executing exact-AST source policy. They fix only the approved
random-source, collision, encoding, verifier/key, unknown version/key, HMAC
mismatch, unavailable/expired/destroyed response, concurrent first-read,
Response-DEK expiry, and credential logging/telemetry failure labels, their
required generic/fail-closed results, and forbidden runtime capability
categories. They do not generate randomness, decode credentials, call a
verifier, compare HMAC tags, read response state, call the Key Service, mutate
first-read state, log credentials, expose endpoints, or authorize recovery.

The Recovery Verifier key lifecycle profile is also represented by inert
descriptors and a non-executing exact-AST source policy. They fix only the
approved 32-byte key size, active/retired/destroyed states, key-separation
labels, forbidden raw-key locations, and lifecycle requirements for
service-selected key identifiers, one active creation version, retired
verify-only keys, no silent fallback, restore proof before destruction,
fail-closed loss, and no Response-DEK authority. They do not generate, store,
select, rotate, or destroy keys, rewrite verifier records, call a Key Service,
expose endpoints, authorize Response-DEK use, or authorize recovery.

The Recovery Verifier verification semantics are also represented by inert
descriptors and a non-executing exact-AST source policy. They fix only the
approved full-length HMAC-SHA-256, constant-time full-tag comparison,
boolean-only result, necessary-not-sufficient HMAC success, canonical input
requirements, unknown-ticket dummy-verification requirement, generic external
non-success behavior, timing-distribution-test requirement, and no-perfect-
indistinguishability claim. They do not compute HMACs, compare tags, execute
dummy verification, return expected tags or partial-match details, read
response state, validate CAPTCHA, call a Key Service, authorize Response-DEK
use, log credentials, expose endpoints, or authorize recovery.

## External design references

- [RFC 4648 — Base-N Encodings](https://www.rfc-editor.org/rfc/rfc4648.html)
- [RFC 2104 — HMAC](https://www.rfc-editor.org/rfc/rfc2104.html)
- [RFC 4231 — HMAC-SHA test vectors](https://www.rfc-editor.org/rfc/rfc4231.html)
- [NIST SP 800-90C — Random Bit Generator Constructions](https://csrc.nist.gov/pubs/sp/800/90/c/final)
- [Python `secrets`](https://docs.python.org/3/library/secrets.html)
- [Python `hmac`](https://docs.python.org/3/library/hmac.html)
