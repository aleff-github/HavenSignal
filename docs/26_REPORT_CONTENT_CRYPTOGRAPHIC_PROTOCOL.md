# 26 — Original Report Content Cryptographic Protocol

## Status

**PROPOSED — consolidated project-owner and independent cryptographic/protocol
review required. No report-content encryption, storage, upload, decryption,
attachment processing, or Report-DEK operation is authorized by this document.**

**OWNER-APPROVED SUBDECISION (2026-08-25) — accepted report text uses the
strict UTF-8/NFC/LF canonical representation defined below as its sole
authoritative original. The pre-normalization browser/wire representation is
not retained. This subdecision does not approve the remaining protocol.**

This proposal defines the version-1 Report-DEK/object-subkey construction,
fixed-length plaintext frames, AEAD envelopes, immutable context binding,
provisional staging, operation capabilities, and failure behavior. It does not
approve a Key Service product/topology, upload parser/sandbox, file acceptance
profile, service authentication, storage durability profile, or endpoint.

## Governing requirements

- `SEC-CONF-001..008`;
- `SEC-ANON-002..004`;
- `SEC-LOG-004..005`, `SEC-LOG-009..012`;
- `SEC-ACCESS-001..015`;
- `SEC-DEL-001..006`;
- `SEC-KEY-001..007`;
- `SEC-FINALIZE-001..006`;
- `SEC-FILE-001..006`;
- `SEC-INPUT-001..006`.

The approved submission sequence in `docs/20`, audit protocol in `docs/23`,
and service boundaries in `docs/19` remain authoritative.

## Selected primitives

Version 1 uses only reviewed library constructions:

- a random 256-bit Report-DEK generated inside the Key Service;
- RFC 5869 HKDF-SHA-256 for distinct per-object AEAD subkeys;
- libsodium XChaCha20-Poly1305-IETF combined mode;
- one random 192-bit nonce and one derived subkey per immutable object;
- RFC 8949 deterministic CBOR for KDF context, AAD, and envelopes;
- SHA-256 only where a public fixed-length structural salt is required, never
  as a substitute for encryption or a secret/content verifier.

There is no algorithm negotiation, caller-selected nonce/key/AAD, plaintext
fallback, development master key, cross-report key reuse, or automatic format
downgrade. A future algorithm requires a new reviewed version.

## Report-DEK and object subkeys

The Key Service generates one independent random 32-byte Report-DEK for each
submission attempt that reaches the approved protected-staging phase. It is not
derived from report content, identifiers, reporter metadata, time, Ticket ID,
Recovery Secret, another DEK, or any infrastructure/application key.

For each immutable report object, the Key Service derives exactly one 32-byte
subkey:

```text
salt = SHA-256(
  "ANONYMOUS_REPORTING_REPORT_DEK_SALT_V1" || report-id
)

prk = HKDF-Extract-SHA-256(salt, report-dek)

info = deterministic-cbor([
  version: 1,
  purpose: "REPORT_OBJECT_AEAD_SUBKEY",
  algorithm: 1,                  ; XCHACHA20_POLY1305_IETF
  report-id: bstr .size 16,
  object-id: bstr .size 16,
  object-kind: "REPORT_TEXT" / "PDF" / "JPEG" / "PNG"
])

object-subkey = HKDF-Expand-SHA-256(prk, info, 32)
```

Internal report/object identifiers are random system-generated values and are
authenticated before use. HKDF input and output remain inside the Key Service.
Derived subkeys are never persisted or exported and are discarded after the
single bounded AEAD operation.

Database uniqueness enforces one `object-id` within an instance and one
`object-kind`/slot assignment within a report. A retry returns the exact stored
envelope; it does not derive a new nonce or encrypt a second value for the same
object identity.

## Canonical report-text frame

The submission boundary canonicalizes report text before encryption:

1. Unicode scalar values only; reject U+0000 and unpaired surrogates;
2. CRLF and CR normalized to LF;
3. Unicode normalized to NFC;
4. at most 5,000 Unicode scalar values;
5. strict UTF-8 without BOM, at most 20,000 bytes.

The reporter-facing preview/validation semantics must not claim that NFC or
line-ending normalization preserves every byte originally typed. Exact
canonical bytes are validated once and are never used for deduplication,
correlation, logging, audit, or a public digest.

After successful validation, `canonical-utf8-report-text` is the authoritative
original report text for encryption, operator viewing, Emergency Export,
hashing inside an authorized export, and cryptographic destruction. The raw
pre-normalization input is discarded before durable persistence and is not
stored, encrypted, queued, logged, audited, backed up, or included as a second
export object. In documentation, “original report text” means this accepted
canonical representation unless a document explicitly says otherwise.

The plaintext frame is exactly 20,005 bytes:

```text
report-text-frame-v1 =
    0x01
 || uint32-big-endian(utf8-byte-length)
 || canonical-utf8-report-text
 || zero-padding-to-exactly-20,005-bytes
```

On decrypt, every byte is validated before text is released: exact frame size,
declared length, zero padding, strict UTF-8, NFC, scalar policy, and 5,000-value
limit. Partial or replacement-decoded text is forbidden.

## Canonical attachment frame

The proposal defines `5 MB` as exactly 5 MiB = 5,242,880 server-observed bytes.
Only bytes already accepted by the separately approved PDF/image structural
profile and isolated sandbox may enter encryption.

Each accepted attachment uses this exact 5,242,890-byte frame:

```text
attachment-frame-v1 =
    0x01
 || object-kind-code             ; 0x01 PDF, 0x02 JPEG, 0x03 PNG
 || uint64-big-endian(original-byte-length)
 || accepted-original-bytes
 || zero-padding-to-exactly-5,242,890-bytes
```

The original filename, browser MIME type, multipart headers, path, and metadata
are absent. On decrypt, the exact total, kind, declared length, zero padding,
and approved server-side object metadata must agree before bytes leave the Key
Service boundary.

Every stored attachment ciphertext is therefore the same size within version
1. The storage boundary can still observe whether attachments exist, their
approved kind/slot, count, creation/deletion timing, and total number of fixed
objects. Hiding those facts would require dummy objects and is not claimed.

## Exact AAD

For every object the Key Service constructs, rather than accepts as raw bytes:

```text
report-object-aad-v1 = [
  version: 1,
  purpose: "ORIGINAL_REPORT_OBJECT",
  algorithm: 1,
  content-profile: 1,
  report-id: bstr .size 16,
  attempt-id: bstr .size 16,
  object-id: bstr .size 16,
  object-kind: controlled-tstr,
  object-slot: uint,              ; text=0, PDF=1, images=2..4
  report-key-handle: bstr .size 32,
  plaintext-frame-length: 20005 / 5242890
]
```

All fields are immutable, authenticated, typed, and context-checked. Mutable
report state/version/lease/time are authorization inputs, not AAD fields.

## Exact ciphertext envelope

```text
report-object-envelope-v1 = [
  version: 1,
  algorithm: 1,
  content-profile: 1,
  report-id: bstr .size 16,
  attempt-id: bstr .size 16,
  object-id: bstr .size 16,
  object-kind: controlled-tstr,
  object-slot: uint,
  report-key-handle: bstr .size 32,
  nonce: bstr .size 24,
  ciphertext-and-tag: bstr
]
```

The ciphertext-and-tag is exactly 20,021 bytes for report text or 5,242,906
bytes for an attachment. The envelope is RFC 8949 deterministic CBOR. Unknown
versions/profiles/algorithms/kinds, alternate CBOR, wrong lengths/types/slots,
extra fields, trailing data, context mismatch, or tag failure are rejected
before any plaintext is released.

Ciphertext objects use server-generated identifiers and create-once storage.
They are never overwritten in place, addressed by a filename, made public, or
served as an ordinary download.

## Non-exportable key model

The application persists only the random opaque 32-byte `report-key-handle`.
The Report-DEK and derived subkeys remain non-exportable inside the Key Service.
Django, Reporter Gateway, Operator Console, workers, sandbox, administrators,
database, blob store, queues, logs, audit, backups, and browser never receive
key bytes.

An internal Key Service wrapping/storage representation remains subject to the
product/topology and non-resurrection proof. No application-visible wrapped DEK
field is permitted.

## Narrow operations and trust separation

- Reporter Gateway may request `CREATE_REPORT_KEY` only for one authenticated,
  currently owned submission attempt and cannot select the handle or key.
- Reporter Gateway may request `ENCRYPT_NEW_REPORT_OBJECT` only while that same
  attempt is in the approved staging state; it cannot decrypt any object.
- The submission reconciler may verify exact envelopes, activate a matching
  committed SEALED key, or destroy a definitively aborted provisional key; it
  cannot decrypt.
- Operator Console may request report-text decryption only for the current
  authenticated OPEN/REOPEN lease, generation, state/version, and durable audit
  receipt.
- Original attachment plaintext may be streamed only from Key Service to one
  authenticated disposable File Processing Sandbox job; it is never returned
  to the Operator Console or exposed as a download.
- Emergency Export Worker receives plaintext only inside its separately
  authorized isolated export workflow.
- Security Workflow Coordinator may destroy only the exact Report-DEK bound to
  one fenced finalization/deletion workflow.

There is no list-all, get-key, export-key, unwrap-any, decrypt-any,
administrator-decrypt, caller-selected object, or state-bypass operation.

## Submission staging

The Key Service creates a `PROVISIONAL` Report-DEK only after the valid
`SUBMISSION_ACCEPTANCE_REQUESTED` receipt. For each accepted object it stores
the minimum idempotency/context record and returns one exact envelope.

The coordinator durably creates ciphertext objects, verifies byte-for-byte
read-back/durability, and commits controlled metadata as
`CIPHERTEXT_STAGED`. After the approved `SUBMISSION_RECEIVED` receipt, the one
PostgreSQL transition commits `SEALED`/`ACCEPTED`. Only then may the Key Service
activate the Report-DEK for future authorized OPEN operations after independently
verifying the exact committed context.

The Key Service never makes a provisional key decrypt-capable. A reconciler
activates an exact committed SEALED binding or destroys a definitively aborted
or absent key. If the state authority is unavailable or ambiguous, the key
remains inert and controlled evidence/alerting is requested; no guess or
availability fallback occurs.

Identical retries return byte-identical envelopes. Mismatched bytes, object
identity, kind/slot, attempt version, idempotency ID, nonce, receipt, or state
fail closed. The Recovery Secret is generated/delivered under `docs/20`/`21`
and is never a report-encryption input.

## Authorized decryption

Before report text disclosure, the Key Service validates:

- authenticated Operator Console service identity and operator session;
- operator role and current report assignment;
- report `OPEN`/approved `REOPEN` state and current state version;
- exact lease ID/generation, server-side idle and absolute expiry;
- exact object envelope and immutable metadata;
- a current context-bound `OPEN_REQUESTED`/`REOPEN_REQUESTED` audit receipt;
- operation idempotency/action nonce and every other required policy gate.

It authenticates and fully validates the frame before returning bounded
plaintext. A tag/frame failure returns no partial output and causes controlled
security handling. A valid receipt is not a bearer capability and cannot
override stale state or lease context.

Attachment decryption uses the same checks plus a one-job sandbox identity and
destination. The operator receives only the separately approved safe
representation. Key Service and sandbox channels must prevent the web process
from redirecting plaintext to an arbitrary endpoint.

## Destruction

`DESTROY_REPORT_KEY` requires the exact fenced workflow, protected state,
durable pre-action audit receipt, current version, idempotency context, and Key
Service policy. Destruction covers the root Report-DEK and therefore every
derived object subkey. There is no per-object subkey record to restore.

After destruction begins, all decrypt operations deny. Completion means every
supported live replica durably confirms deletion and the non-resurrection proof
accepts the result. Unknown outcome is resolved forward; no key is recreated.
Ciphertext deletion is separate and retryable, but retained ciphertext remains
cryptographically unusable.

## Failure behavior

| Failure | Required result |
|---|---|
| Invalid text/file/profile/size | Reject before key/object persistence |
| Audit or Key Service unavailable | No key/object creation or plaintext fallback |
| Duplicate exact encryption request | Return original byte-identical envelope |
| Duplicate mismatched request/nonce/context | Reject and controlled security event |
| Ciphertext durability uncertain | Never commit SEALED or issue credentials |
| SEALED commit absent/aborted | Keep provisional key inert; destroy when definitive |
| State ambiguous/unavailable | Keep inert/deny decrypt; never guess |
| Wrong receipt/state/lease/generation/service | Deny decrypt without oracle detail |
| Tag/AAD/frame failure | No plaintext; controlled alert/evidence |
| Sandbox unavailable | No original attachment delivery or ordinary fallback |
| Key destruction uncertain | Deny every use and resolve only forward |
| Old snapshot/replica exposes a usable key | Release-blocking Key Service acceptance failure |

## Required tests before enablement

- RFC 5869 SHA-256 vectors, deterministic KDF context, per-report/per-object
  separation, and no cross-purpose derived-key equality;
- pinned libsodium XChaCha20-Poly1305 vectors and independent fixtures;
- exact deterministic-CBOR AAD/envelope bytes and closed-schema rejection;
- fixed text/attachment ciphertext sizes at all boundary lengths;
- UTF-8/NFC/line-ending/length framing and attachment kind/length/padding checks;
- exact reuse of the accepted canonical report-text bytes for OPEN and Emergency
  Export, with no durable or encrypted pre-normalization copy;
- single encryption per object, random nonce uniqueness, byte-identical retry,
  and synchronized multi-process idempotency races;
- bit alteration and cross-report/attempt/object/kind/slot/key-handle substitution
  fail before plaintext;
- Reporter Gateway cannot decrypt and Operator Console cannot receive original
  attachment bytes or redirect the sandbox stream;
- crash injection at every staging/audit/SEALED/activation boundary produces
  only the approved state and never issues credentials early;
- wrong/stale operator, state, version, lease, generation, receipt, idempotency,
  sandbox job, and export/finalization race fail closed;
- Report-DEK destroy/replication/snapshot/restore/rollback/disaster-recovery tests
  make every retained ciphertext permanently unusable;
- no plaintext, filename, key, nonce request, content digest, raw exception, or
  reporter metadata enters logs/audit/alerts/traces/queues/temp files.

SQLite, one process, mock deletion, or a local plaintext crypto adapter is
insufficient for release acceptance.

## Consolidated decisions awaiting the pre-code gate

1. random 256-bit non-exportable Report-DEK with RFC 5869 HKDF-SHA-256
   per-object subkeys;
2. XChaCha20-Poly1305-IETF combined mode with one random 192-bit nonce per
   immutable object;
3. canonical fixed-size 20,005-byte text and 5,242,890-byte attachment frames,
   defining `5 MB` as exactly 5 MiB; within this choice, NFC/LF normalization
   and the absence of a second raw-text copy are already owner-approved;
4. deterministic-CBOR KDF/AAD/envelope schemas and fixed ciphertext sizes;
5. provisional/inert staging, exact SEALED activation, narrowly separated
   decrypt paths, and no application-visible wrapped DEK;
6. forward-only Report-DEK destruction and the stated idempotency/concurrency
   behavior.

Independent cryptographic review, Key Service product/topology/HSM and actual
non-resurrection PoC, service authentication, file/sandbox profiles, storage
durability, PostgreSQL concurrency, audit implementation, and deployment remain
release gates after owner approval.

## External design references

- [RFC 5869 — HKDF](https://www.rfc-editor.org/rfc/rfc5869.html)
- [RFC 2104 — HMAC](https://www.rfc-editor.org/rfc/rfc2104.html)
- [RFC 8949 — Concise Binary Object Representation](https://www.rfc-editor.org/rfc/rfc8949.html)
- [libsodium — XChaCha20-Poly1305](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)
