# 28 — Emergency Export Cryptographic Protocol

## Status

**PROPOSED — consolidated project-owner and independent cryptographic/protocol
review required. No Emergency Export endpoint, key, signing capability,
plaintext release, or downloadable artifact is authorized by this document.**

This proposal fixes the version-1 request binding, package profile, public-key
encryption, manifest signature, key separation, fenced workflow, encrypted
staging, delivery, cleanup, and verification behavior. It does not approve an
Alert Service, production `age` binary/library, HSM/signing product, operator
workstation, storage backend, service authentication, or deployment topology.

## Governing requirements

- `SEC-CONF-001..008`;
- `SEC-LOG-004..005`, `SEC-LOG-009..012`;
- `SEC-ACCESS-001..015`;
- `SEC-AUTH-003..008`;
- `SEC-KEY-005..007`;
- `SEC-FINALIZE-004`, `SEC-FINALIZE-006`;
- `SEC-EXPORT-001..006`;
- `SEC-ALERT-001..003`;
- `SEC-BROWSER-001..002`.

The owner-approved audit protocol in `docs/23`, the proposed step-up protocol
in `docs/25`, report-content profile in `docs/26`, and Key Service acceptance
plan in `docs/27` remain authoritative within their stated status and gates.

## Version-1 construction

Version 1 proposes:

- an uncompressed POSIX.1-1988 `ustar` package stream under the closed profile
  below;
- binary `age-encryption.org/v1` encryption to exactly one preconfigured native
  X25519 organization recipient;
- an RFC 8785 JSON Canonicalization Scheme (`JCS`) manifest encoded as UTF-8;
- a tagged RFC 9052 `COSE_Sign1` detached signature over the exact manifest
  bytes, using pure Ed25519/EdDSA from RFC 8032 and RFC 9053;
- SHA-256 for exact content and final encrypted-artifact hashes.

There is no passphrase recipient, armored output, OpenPGP fallback, password
ZIP, compression, algorithm negotiation, caller-selected recipient, unsigned
mode, second raw-text copy, or development signing/encryption key. A future
algorithm or package format requires a new independently reviewed version.

## Exact export-request descriptor

Before WebAuthn step-up, the server freezes this RFC 8949 deterministic-CBOR
descriptor. All maps are closed, duplicate keys and alternate encodings are
rejected, and ordering follows deterministic CBOR:

```text
emergency-export-request-v1 = [
  version: 1,
  purpose: "EMERGENCY_EXPORT_REQUEST",
  export-id: bstr .size 16,
  report-id: bstr .size 16,
  ticket-id: controlled-tstr,
  report-state: "OPEN",
  report-state-version: uint,
  lease-id: bstr .size 16,
  lease-generation: uint,
  operator-id: bstr .size 16,
  session-id: bstr .size 16,
  reason-code: controlled-tstr,
  protected-note: bstr .size (1..4000),
  accepted-at: controlled-rfc3339-utc-tstr,
  export-time: controlled-rfc3339-utc-tstr,
  objects: [
    [object-id: bstr .size 16,
     kind: controlled-tstr,
     slot: uint,
     envelope-sha256: bstr .size 32]
  ],
  age-recipient-kid: bstr .size 16,
  manifest-signing-kid: bstr .size 16
]
```

`protected-note` is nonempty strict UTF-8 after NUL/scalar rejection, CRLF/CR
to LF, NFC normalization, and the 1,000-scalar-value limit. Its 4,000-byte field
cap is framing capacity, not permission to exceed 1,000 scalar values. The full
descriptor is passed transiently to the Step-Up service as the exact
`artifact-bytes` for `EMERGENCY_EXPORT` under `docs/25`; it is not copied to
audit or logs. A plain content hash of the note is forbidden.

The object list is ordered by controlled slot: report text `0`, PDF `1`, then
images `2..4`. It binds the immutable ciphertext envelopes, not caller-supplied
filenames or plaintext hashes. Any later change to content, context, reason,
note, lease, state/version, key ID, or object list invalidates the step-up and
requires a new request.

## Package contents

The uncompressed logical package contains only these regular files, in order
when present:

```text
report.txt
attachments/document.pdf
attachments/image-1.jpg or attachments/image-1.png
attachments/image-2.jpg or attachments/image-2.png
attachments/image-3.jpg or attachments/image-3.png
manifest.json
manifest.cose
```

`report.txt` is byte-for-byte the owner-approved authoritative strict
UTF-8/NFC/LF report text from `docs/26`, with no BOM or added newline. Attachment
files are byte-for-byte the accepted original bytes after the approved
structural admission pipeline. Browser filenames, multipart metadata, safe-view
derivatives, thumbnails, Response Notes, Recovery Secrets, keys, and raw
pre-normalization text are absent.

Version 1 excludes full reopening and Emergency Export operator notes. The
manifest may carry only allowlisted reopening/export reason codes, controlled
timestamps, and system-generated identifiers needed for traceability. A future
legal/operational requirement to include full notes requires explicit owner and
privacy review and a new package profile.

## Closed `ustar` profile

The package is streamed as POSIX.1-1988 `ustar`, without compression:

- ASCII paths exactly from the list above and no directory entries;
- regular-file entries only; no symlink, hardlink, device, FIFO, sparse,
  duplicate, absolute, `..`, backslash, drive-prefix, GNU, PAX, or extension
  entry;
- `mode=0400`, `uid=0`, `gid=0`, empty owner/group names, and `mtime=0`;
- exact known size per entry, standard header checksum, zero data padding to a
  512-byte block, exactly two end-marker zero blocks, then only the exact zero
  fill required to reach the next 10,240-byte record boundary;
- no bytes after that record boundary and no alternate member ordering.

The implementation must select `USTAR_FORMAT` explicitly; a library default is
not accepted. A verifier first enforces this closed archive profile and bounded
member sizes without extracting paths, then verifies the manifest signature
and every content hash. General-purpose archive extraction is not the
verification procedure.

## Canonical manifest

`manifest.json` is the exact RFC 8785 JCS UTF-8 encoding of one closed-schema
I-JSON object. Duplicate or unknown fields, floats, negative values, unsafe
integers, noncanonical strings, alternate time/identifier encodings, and
trailing bytes are rejected. It contains:

```text
schema = "anonymous-reporting/emergency-export-manifest/v1"
package_profile = "posix-ustar-closed-v1"
export_id = lower-case hexadecimal 16-byte identifier
ticket_id = canonical public Ticket ID
accepted_at = exact controlled UTC timestamp
export_time = exact controlled UTC timestamp frozen in the request
operator_id = lower-case hexadecimal internal 16-byte identifier
reason_code = allowlisted system code
requested_audit_event_id = lower-case hexadecimal 16-byte identifier
requested_audit_entry_digest = lower-case hexadecimal SHA-256
age_format = "age-encryption.org/v1"
age_recipient_type = "X25519"
age_recipient_kid = lower-case hexadecimal 16-byte key ID
signature_format = "COSE_Sign1-detached-v1"
signature_algorithm = "EdDSA-Ed25519"
manifest_signing_kid = lower-case hexadecimal 16-byte key ID
history = ordered controlled reopening events, or an empty array
contents = ordered array of path, controlled media type, byte length, SHA-256
```

Timestamps use UTC RFC 3339 with exactly six fractional digits and terminal
`Z`. JSON integer sizes are restricted to nonnegative values no greater than
`2^53 - 1`. Content SHA-256 values cover the exact file bytes before `ustar`
padding. The manifest does not hash or list itself or `manifest.cose`; its
signature binds it, while `age` authenticates the whole package stream.

Allowed media types are exactly `text/plain;charset=utf-8`, `application/pdf`,
`image/jpeg`, and `image/png`. `history` contains only controlled event type,
system reason code, server timestamp, and system-generated operator identifier;
it never contains a full protected note or reporter-controlled value.

## Manifest signature

The Export Manifest Signer owns a dedicated non-exportable Ed25519 private key.
It is distinct from audit, receipt, checkpoint, TLS, WebAuthn, organization
export-decryption, Key Service, Report-DEK, and Response-DEK keys.

The public key is represented as a deterministic RFC 9053 Ed25519 COSE Key. Its
identifier is the first 16 bytes of SHA-256 over those exact public COSE Key
bytes. `manifest.cose` is deterministic CBOR with tag 18 and this exact form:

```text
COSE_Sign1 = 18([
  protected: deterministic-cbor({1: -8, 4: manifest-signing-kid}),
  unprotected: {},
  payload: null,
  signature: bstr .size 64
])

Sig_structure = [
  "Signature1",
  protected,
  external_aad: h'',
  payload: exact-manifest.json-bytes
]
```

The signer accepts only an authenticated `SIGN_EXPORT_MANIFEST` request bound
to one current authorized ExportJob, validates the closed manifest schema and
request/audit/key context, chooses its own active key, and returns only the
COSE object. It has no report-decryption or arbitrary byte-signing interface
and does not persist or log the manifest, its hashes, or signing input. The
organization preserves an authenticated out-of-band registry of public
verification keys and validity periods; a public key carried with the artifact
alone is not a trust anchor.

## `age` encryption and recipient key

The complete `ustar` stream is encrypted in binary form under
`age-encryption.org/v1` to exactly one native X25519 recipient. The active
recipient is selected only from approved server configuration. Its key ID is
the first 16 bytes of SHA-256 over the exact lowercase canonical ASCII `age1...`
recipient string.

The organization recipient private key is generated, held, backed up if
approved, and used only outside the application/Export Worker trust domain. It
must be absent from Django, PostgreSQL, blob storage, Key Service, Audit Service,
Alert Service, Export Worker, signing service, deployment secrets, VM/container
images, logs, and application backups. The production acceptance ceremony must
prove successful outside-platform decryption of a canary and absence of the
private identity from every platform secret inventory.

Recipient installation or rotation requires an authenticated distinct-role
quorum of an Application Administrator and Infrastructure / Key Custodian,
out-of-band comparison of the full recipient fingerprint, a canary
encrypt/decrypt/verify ceremony, and an auditable activation. Neither role may
activate a replacement alone. A descriptor already bound to an old key ID
cannot silently switch to the new key. New exports use only the active key;
previous artifacts are not re-encrypted by the platform. The organization owns
retention and destruction of historical private keys according to its external
export policy.

The exact `age` implementation and version must be pinned, supported, tested
against official format vectors, scanned as a release dependency, and invoked
without shell interpolation. Only the native X25519 recipient profile is
accepted for version 1; plugin, passphrase, SSH, hybrid, multiple-recipient,
armored, or unknown stanzas fail closed.

## Fenced and resumable workflow

`EmergencyExportJob` is a persisted, immutable-context workflow with a random
16-byte ID, current report/lease/generation/state-version binding, object list,
key IDs, reason code, encrypted protected-note reference, server timestamps,
idempotency ID, audit/alert references, encrypted-object reference/hash/size,
state, version, worker fencing token, heartbeat, and absolute deadline.

Exactly one active security operation may fence a report. PostgreSQL uniqueness,
row locks, state-version checks, and monotonic fencing ensure that export,
finalization, deletion, reopening, and a second export have one winner. The
operation fence is never a process-local lock. `FINALIZING` always denies a new
export. Finalization may start only after an export job is terminal and its Key
Service export capability is revoked.

The proposed order is:

1. validate authenticated operator, current OPEN lease/generation/state,
   allowlisted reason, protected note, CSRF, and CAPTCHA;
2. freeze the exact request descriptor and complete its WebAuthn step-up;
3. append `EMERGENCY_EXPORT_REQUESTED` and obtain the context-bound receipt;
4. obtain durable acceptance of the allowlisted administrator alert;
5. in one PostgreSQL transaction, lock report/lease/step-up/job rows, revalidate
   every binding and server time, consume the single-use step-up, create the
   immutable `AUTHORIZED` job, and acquire the report operation fence;
6. append truthful `EMERGENCY_EXPORT_AUTHORIZED`; no plaintext is released if
   this required event cannot be durably accepted under the approved audit
   policy;
7. the isolated worker obtains only the exact job-scoped Key Service operation,
   streams authenticated report objects into the closed `ustar` writer, hashes
   exact plaintext entries, creates/signs the manifest, and streams the entire
   package directly through `age` into create-once encrypted staging;
8. close and verify tool success, exact output size bounds, encrypted-object
   durability, and SHA-256 over the final encrypted bytes;
9. append `EMERGENCY_EXPORT_COMPLETED` with the encrypted artifact hash and
   obtain its durable receipt before making the artifact available;
10. revalidate the same authenticated operator session, current OPEN lease,
    report state/version, job/fence, artifact hash, and completion receipt, then
    permit one POST-initiated response stream;
11. at response start atomically mark the delivery consumed; after stream close
    or failure, delete encrypted staging, revoke the job capability, release the
    fence, and append a truthful controlled outcome.

The job ownership transaction and initial Key Service authorization must both
complete before the `EMERGENCY_EXPORT_REQUESTED` receipt's `authorizes-until`
deadline. The resulting non-bearer, mTLS-bound Key Service job capability is
valid for no longer than the export's 15-minute absolute deadline and remains
subject to current job, report, lease, generation, state/version, and fencing
checks. Receipt expiry never allows a new grant or retry to bootstrap another
job; failure to obtain the grant in time aborts the export.

No plaintext report or package is ever written to disk, object storage, queue,
database, log, audit, trace, alert, or crash dump. Report/attachment plaintext
is processed in bounded memory and piped directly through `ustar` and `age`.
The final encrypted artifact may be staged briefly because its hash and durable
audit completion must precede release.

## Worker and delivery boundary

The Export Worker is isolated from Django web processes and has:

- no organization private recipient key, shell, interactive login, general
  Report-DEK operation, arbitrary object selection, or broad blob listing;
- network access only to the specifically allowlisted state, Key, Audit, Alert,
  Manifest Signer, and encrypted-staging endpoints under separate mTLS identity;
- no swap, core dumps, ptrace, shared writable volume, inherited production
  credentials, reporter-controlled path, or reusable plaintext workspace;
- fixed CPU/memory/output/time ceilings and a maximum 15-minute absolute job
  deadline with short authenticated heartbeats.

The download response uses `Cache-Control: no-store`, a fixed
`Content-Disposition` name `emergency-export.age`, and
`Content-Type: application/octet-stream`. It is not exposed by a public or
secret-bearing URL, does not support Range, does not embed the Ticket ID, and
cannot be resumed or downloaded a second time. An interrupted transfer requires
a wholly new export authorization; availability does not override the
confidentiality/fencing model.

Encrypted staging expires five minutes after completion and never beyond the
job's 15-minute absolute deadline. It is deleted immediately after the one
response stream terminates, successfully or otherwise. A worker/job reconciler
runs at least once per minute. It revokes expired capabilities and deletes
orphaned encrypted objects using exact object IDs. Persistent cleanup failure is
audited and alerted; it never makes an artifact downloadable without the
required state and receipt.

## Failure behavior

| Failure | Required result |
|---|---|
| Invalid state/lease/CAPTCHA/reason/note | No audit-authorized export or plaintext release |
| Step-up/descriptor mismatch or expiry | Deny; require a fresh complete request |
| Audit receipt unavailable/invalid | No job ownership, decrypt, generation, or download |
| Alert durable acceptance unavailable | No job ownership or export generation |
| Export/finalization/deletion race | One PostgreSQL-fenced winner; loser fails closed |
| Key ID/configuration changes after binding | Abort; never substitute another recipient or signer |
| Key Service, signer, or `age` unavailable | No plaintext fallback; abort and clean encrypted partial output |
| Object/tag/frame/context mismatch | No partial plaintext/package release; controlled failure handling |
| Worker crash/timeout | Revoke capability, delete encrypted partial/staging object, release only after terminal reconciliation |
| Encrypted durability/hash uncertain | No COMPLETED event or download |
| COMPLETED audit unavailable | Keep artifact quarantined only until cleanup deadline; never release it |
| Lease/session expires before download | No release; clean staging and require a new export |
| Download disconnects | Consume the delivery, delete staging, require a new full authorization |
| Cleanup fails | Artifact remains inaccessible; retry and send controlled alert |
| Organization cannot decrypt/verify canary | Release-blocking configuration failure |

Every failure event contains only controlled identifiers, stage/result codes,
key IDs, sizes, and encrypted-artifact digest where available. It never contains
report text, attachment bytes/hashes, full notes, filenames, keys, command
output, untrusted tool errors, request headers, or paths.

## Verification outside the platform

The organization receives a separate, reviewed verifier procedure/tool that:

1. decrypts the binary `age` file in an isolated evidence-handling environment;
2. parses without extraction and accepts only the closed `ustar` profile;
3. requires exactly one `manifest.json` and one `manifest.cose` in the final
   positions and no unknown/duplicate entries;
4. resolves `manifest_signing_kid` only through the authenticated external key
   registry and verifies detached COSE Sign1/Ed25519 over the exact manifest;
5. reparses and reserializes the manifest under RFC 8785 and requires
   byte-for-byte equality;
6. validates every schema value, path, size, SHA-256, media type, entry order,
   and absence of unlisted content before any controlled extraction;
7. compares the encrypted-artifact hash and audit reference with separately
   obtained authorized audit evidence when available.

The tooling must never report a signature/hash success as proof of universal
legal admissibility. It proves only the specified technical bindings.

## Required tests before enablement

- official `age` v1 vectors, native X25519 stanza/header/payload validation,
  truncation/final-chunk failure, unknown/multiple recipient rejection, and
  randomized-file behavior;
- RFC 8785 vectors and rejection of duplicate fields, unsafe numbers,
  noncanonical Unicode/string handling, unknown fields, and trailing bytes;
- RFC 9052/9053 and RFC 8032 vectors for tagged detached COSE Sign1, protected
  algorithm/key ID, wrong key, altered manifest, malformed CBOR, and signature;
- byte-pinned closed `ustar` fixtures for every allowed object combination,
  boundary size, padding, order, header field, and forbidden entry type/path;
- exact canonical report bytes and accepted attachment bytes match manifest
  hashes after independent decryption; no raw text or safe-view derivative is
  present;
- descriptor mutation across note, reason, object set, envelope, operator,
  session, lease, state/version, recipient, and signer invalidates step-up;
- one synchronized winner for export/export, export/finalization,
  export/deletion, lease expiry, stale worker, duplicate POST, and delayed retry;
- crash injection at every audit, alert, fence, decrypt, tar, sign, encrypt,
  staging, completion, delivery, and cleanup boundary produces only an approved
  state and never releases partial/plaintext content;
- filesystem, process, swap, core, queue, log, audit, alert, trace, proxy, and
  backup inspection finds no plaintext package/member, full note, original
  filename, private key, or plaintext hash;
- recipient/signing rotation rejects stale descriptors and proves historical
  verification through externally preserved public keys;
- production-equivalent canary ceremony proves organization-side decrypt,
  signature verification, content verification, and platform-side absence of
  the recipient private key;
- download requires the exact current operator/session/OPEN lease and completion
  receipt, is no-store/POST-only/non-resumable, and cannot be replayed.

General archive extraction, mock signing, a fixed local success receipt,
password encryption, a plaintext temporary tar, a development private key, or
an in-process Django export worker is insufficient for release acceptance.

## Consolidated decisions awaiting the pre-code gate

1. binary single-recipient native-X25519 `age` v1 encryption;
2. closed uncompressed POSIX `ustar` package with fixed safe paths/metadata;
3. RFC 8785 manifest and detached COSE Sign1/Ed25519 signature;
4. exclusion of full protected operator notes from package profile v1;
5. exact deterministic-CBOR request binding to content envelopes, context, and
   active recipient/signing key IDs;
6. distinct-role recipient-key activation and external private-key custody;
7. fenced 15-minute job, streaming plaintext only into encryption, brief
   encrypted-only staging, durable COMPLETED receipt before one-shot delivery;
8. outside-platform decrypt/signature/content verification ceremony.

Independent cryptographic/protocol review, dependency/toolchain review, Alert
Service approval, Key Service implementation/PoC, signer/HSM selection,
organization key-custody procedure, PostgreSQL concurrency, audit deployment,
workstation/download handling, and production isolation remain release gates
after owner approval.

## External design references

- [C2SP age file-encryption format](https://age-encryption.org/v1)
- [RFC 8785 — JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html)
- [RFC 9052 — COSE structures and processing](https://www.rfc-editor.org/rfc/rfc9052.html)
- [RFC 9053 — COSE initial algorithms](https://www.rfc-editor.org/rfc/rfc9053.html)
- [RFC 8032 — EdDSA](https://www.rfc-editor.org/rfc/rfc8032.html)
- [Python `tarfile` supported formats](https://docs.python.org/3/library/tarfile.html#supported-tar-formats)
