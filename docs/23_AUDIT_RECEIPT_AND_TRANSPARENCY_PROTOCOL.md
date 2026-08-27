# 23 — Audit Receipt and Transparency Protocol

## Status

**OWNER-APPROVED — project-owner decision recorded on 2026-08-25;
independent cryptographic/protocol review remains required. No Audit Service or
receipt-gated operation is authorized for production by this document alone.**

This proposal selects a version-1 event encoding, durable-acceptance receipt,
anti-replay policy, append-only Merkle construction, independently witnessed
checkpoint cadence, and signing-key separation. It does not approve an Audit
Service product, database/topology, HSM, service-authentication mechanism,
alert transport, deployment, or application endpoint.

## Governing requirements

This proposal applies primarily to:

- `SEC-LOG-001..012`;
- `SEC-CONF-006..008`;
- `SEC-ANON-002..004`;
- `SEC-ACCESS-010..015`;
- `SEC-AUTH-005..007`;
- `SEC-DEL-001..006`;
- `SEC-KEY-002..007`;
- `SEC-FINALIZE-001..006`;
- `SEC-EXPORT-001..005`;
- `SEC-ALERT-001..003`.

`docs/01_SECURITY_BASELINE.md` remains normative. A conflict stops
implementation and returns the decision to the project owner.

## Standards profile; no invented cryptography

Version 1 composes these published constructions:

- deterministic CBOR under RFC 8949 for exact event and claim bytes;
- COSE `COSE_Sign1` under RFC 9052 and RFC 9053;
- Ed25519 / COSE `EdDSA` (`alg = -8`) under RFC 8032;
- SHA-256 under FIPS 180-4;
- the RFC 9162 SHA-256 binary Merkle tree, including domain-separated leaf
  and node hashes, inclusion proofs, and consistency proofs;
- RFC 9942 COSE Receipts using registered VDS `RFC9162_SHA256` (`vds = 1`)
  for independently verifiable inclusion and consistency evidence.

The proposal defines an application profile around those constructions. It
must not replace them with a home-grown signature, hash chain, ambiguous JSON
serialization, unsigned receipt, fixed success token, or shared application
secret.

## Security outcome

A protected action may proceed only when the consuming service verifies all of
the following:

1. the Audit Collector durably committed the exact allowlisted event;
2. a valid online receipt-signing key signed the exact durable-acceptance
   claims after the event and receipt bytes were prepared for the same commit;
3. the event binds the authenticated caller, actor where applicable, object,
   operation, current state/version, current lease generation where applicable,
   idempotency identifier, action nonce, and server-authoritative validity;
4. the receipt and event hashes match exactly;
5. the receipt is still usable for that one current operation and is not a
   bearer capability by itself;
6. the Audit Service remains inside its maximum checkpoint/inclusion delay and
   an independent verifier is still accepting consistent checkpoints.

Later RFC 9942 inclusion and consistency receipts make mutation, gaps,
forks/equivocation, and suffix truncation independently detectable. Scheduled
empty-tree heartbeats make audit cessation detectable even when no application
events occur.

## Trust boundaries and negative capabilities

The protocol separates:

- **Event caller** — may append only event families allowed for its authenticated
  service profile; cannot select signing keys, event positions, or timestamps;
- **Audit Collector / durable store** — validates, orders, and commits events;
  cannot expose report content and cannot use application decryption keys;
- **Online receipt signer** — signs only collector-constructed acceptance
  claims for a transaction pending durable commit;
- **Checkpoint signer** — independently verifies committed tree growth and
  signs checkpoints and RFC 9942 proofs; it cannot append or rewrite events;
- **Independent verifier/witness** — retains checkpoints, public-key manifests,
  inclusion/consistency evidence, and liveness state; it cannot append events
  or read report content;
- **Application Administrator audit reader** — may read authorized controlled
  audit records but cannot mutate history, sign receipts, or read reports;
- **Protected service** — verifies the event and receipt for one operation; it
  cannot ask the audit store to rewrite or backdate evidence.

Append, read, receipt-sign, checkpoint-sign, witness, retention-expiry, and
alert credentials are distinct. The report application, Operator Console, and
Application Administrator have no UPDATE, DELETE, TRUNCATE, backdate,
retention-shortening, receipt-signing, or checkpoint-signing capability.

## Exact version-1 append request

All byte strings have exact lengths. All text values are uppercase ASCII values
from a closed registry. There are no arbitrary maps, floating-point values,
negative integers, indefinite-length items, Unicode normalization choices,
unknown trailing fields, or optional extensions in version 1.

The caller sends deterministic CBOR matching this semantic array:

```text
audit-append-request-v1 = [
  version: 1,
  event-type: controlled-tstr,
  actor-kind: "NONE" / "OPERATOR" / "APPLICATION_ADMIN" / "SERVICE",
  actor-id: bstr .size 16 / nil,
  object-kind: controlled-tstr,
  object-id: bstr .size 16,
  operation: controlled-tstr,
  state-code: controlled-tstr / nil,
  state-version: uint / nil,
  lease-id: bstr .size 16 / nil,
  lease-generation: uint / nil,
  idempotency-id: bstr .size 16,
  action-nonce: bstr .size 32,
  reason-code: controlled-tstr / nil,
  artifact-binding: bstr .size 32 / nil,
  outcome-code: controlled-tstr / nil
]
```

The authenticated service identity supplies `caller-profile` and
`caller-instance-id`; values in the request cannot override them. Operator or
administrator `actor-id` must match the authenticated application context.
Anonymous submission and recovery events use `actor-kind = "NONE"` and
`actor-id = nil`; no reporter identity is created.

The caller generates `idempotency-id` and `action-nonce` independently with the
operating-system CSPRNG. They are unrelated to reporter input, IP address,
User-Agent, Ticket ID, Recovery Secret, report content, or time. They are sent
only through the authenticated service channel and never appear in URLs or
application logs.

`artifact-binding` is required only by an event profile that acts on exact
protected bytes. It must be the opaque 32-byte output of the separately
approved step-up/artifact-binding construction. A plain unkeyed digest of a
short or guessable Response Note must not be placed in permanent audit. That
construction remains independently OPEN.

## Exact version-1 durable event

After authentication and policy validation, the collector constructs:

```text
audit-event-v1 = [
  version: 1,
  log-id: bstr .size 32,
  event-id: bstr .size 16,
  leaf-index: uint,
  event-type: controlled-tstr,
  caller-profile: controlled-tstr,
  caller-instance-id: bstr .size 16,
  actor-kind: controlled-tstr,
  actor-id: bstr .size 16 / nil,
  object-kind: controlled-tstr,
  object-id: bstr .size 16,
  operation: controlled-tstr,
  state-code: controlled-tstr / nil,
  state-version: uint / nil,
  lease-id: bstr .size 16 / nil,
  lease-generation: uint / nil,
  idempotency-id: bstr .size 16,
  action-nonce: bstr .size 32,
  reason-code: controlled-tstr / nil,
  artifact-binding: bstr .size 32 / nil,
  occurred-at-ms: uint,
  authorization-not-after-ms: uint / nil,
  outcome-code: controlled-tstr / nil
]
```

`log-id`, `event-id`, `leaf-index`, caller identity, both timestamps, and the
authorization lifetime are collector-controlled. Time is Unix time in
milliseconds from the collector's approved server clock. Clock rollback,
overflow, or unavailable trusted time fails issuance closed.

Every event is encoded with RFC 8949 core deterministic encoding. A decoder
must reject any non-deterministic representation, wrong type/length, unknown
version, unknown registry value, duplicate semantic representation, extra
field, or non-minimal integer.

The exact RFC 9162 leaf hash is:

```text
leaf-hash = SHA-256(0x00 || deterministic-cbor(audit-event-v1))
```

Internal object and actor IDs are random/system-generated 16-byte identifiers.
They are not public Ticket IDs, secrets, usernames, email addresses, filenames,
or reporter-supplied identifiers.

## Event registry and phases

Version 1 allows only the event names already required by
`docs/08_AUDIT_LOGGING.md`, the submission events approved by `docs/20`, and
the following request/outcome companions needed to represent disclosure
truthfully:

- `SUBMISSION_ACCEPTANCE_REQUESTED`, `SUBMISSION_RECEIVED`,
  `SUBMISSION_ACCEPTANCE_FAILED`;
- `CLAIM`, `CLAIM_EXPIRED`;
- `OPEN_REQUESTED`, `OPEN_AUTHORIZED`, `OPEN_COMPLETED`, `OPEN_FAILED`;
- `ATTACHMENT_VIEW_REQUESTED`, `ATTACHMENT_VIEWED`,
  `ATTACHMENT_VIEW_FAILED`;
- `INTERRUPTED`;
- `REOPEN_REQUESTED`, `REOPEN_AUTHORIZED`, `REOPEN_COMPLETED`,
  `REOPEN_FAILED`;
- `RESPONSE_RETRIEVAL_REQUESTED`, `RESPONSE_RETRIEVAL_COMPLETED`,
  `RESPONSE_RETRIEVAL_FAILED`;
- `EMERGENCY_EXPORT_REQUESTED`, `EMERGENCY_EXPORT_AUTHORIZED`,
  `EMERGENCY_EXPORT_COMPLETED`, `EMERGENCY_EXPORT_FAILED`;
- `FINALIZATION_REQUESTED`, `FINALIZATION_AUTHORIZED`,
  `FINALIZATION_COMPLETED`, `FINALIZATION_FAILED`;
- `RESPONSE_AVAILABLE`, `REPORT_KEY_DESTROYED`;
- `CONTENT_DELETE_STARTED`, `CONTENT_DELETE_COMPLETED`,
  `CONTENT_DELETE_FAILED`;
- `DELETE_REPORT_REQUESTED`, `DELETE_REPORT_AUTHORIZED`,
  `DELETE_REPORT_COMPLETED`, `DELETE_REPORT_FAILED`;
- `SECURITY_CONFIGURATION_CHANGED`, `OPERATOR_AUTHENTICATION_EVENT`,
  `ADMIN_AUDIT_ACCESS`.

Each event has a version-controlled profile fixing the allowed caller, actor,
object, operation, source states, required/null fields, reason/outcome codes,
and whether it may authorize a protected action. Adding or weakening a profile
is a reviewed protocol-version change, not a runtime configuration toggle.

REQUESTED means only that an operation was requested and durably recorded.
AUTHORIZED means the separately required policy controls authorized it.
COMPLETED means the protected effect actually occurred. FAILED means it did
not complete or requires controlled recovery. No phase may be inferred or
written early merely because an earlier phase succeeded.

## Proposed authorization lifetimes

The durable event and signature remain historical evidence after the following
authorization window closes. Only operational use expires:

| Pre-action event | `authorization-not-after-ms` |
|---|---:|
| `SUBMISSION_ACCEPTANCE_REQUESTED` | accepted time + 15 minutes |
| `SUBMISSION_RECEIVED` | accepted time + 60 seconds |
| `OPEN_REQUESTED`, `REOPEN_REQUESTED` | accepted time + 30 seconds |
| `ATTACHMENT_VIEW_REQUESTED` | accepted time + 30 seconds |
| `RESPONSE_RETRIEVAL_REQUESTED` | accepted time + 30 seconds |
| `FINALIZATION_REQUESTED` | accepted time + 60 seconds |
| `EMERGENCY_EXPORT_REQUESTED` | accepted time + 60 seconds |
| `DELETE_REPORT_REQUESTED` | accepted time + 60 seconds |
| `REPORT_KEY_DESTROYED` before response publication | accepted time + 5 minutes |

Every other event uses `nil` and cannot authorize a protected operation.
Validity is non-sliding. Retry does not extend it. The consumer uses its own
approved server clock and rejects a receipt issued too far in the future,
expired, or outside configured clock-skew bounds. The exact clock-skew ceiling
remains a deployment review item; it cannot be caller-controlled.

## Durable-acceptance receipt

The collector returns a tagged `COSE_Sign1` only after the database/storage
transaction containing the event, exact receipt bytes, unique replay keys, and
current log position commits durably.

Its deterministic CBOR payload is:

```text
audit-acceptance-claims-v1 = [
  version: 1,
  log-id: bstr .size 32,
  event-id: bstr .size 16,
  leaf-index: uint,
  leaf-hash: bstr .size 32,
  accepted-at-ms: uint,
  authorization-not-after-ms: uint / nil
]
```

Required protected COSE headers are:

```text
alg = -8                         ; EdDSA
kid = bstr .size 16              ; collector-selected receipt key ID
content-type = "application/vnd.anonymous-reporting.audit-acceptance+cbor;v=1"
```

The unprotected header map is empty, the external AAD is the empty byte string,
the curve is Ed25519, and the signature is exactly 64 bytes. Unknown headers,
critical headers, algorithms, curves, key IDs, content types, payload versions,
or alternate encodings fail closed. The implementation uses a mature reviewed
COSE/cryptographic library and RFC test vectors; it does not implement curve
arithmetic itself.

The receipt is not a bearer token. A consumer receives the exact event bytes
alongside the receipt and must recompute the leaf hash, verify the signature,
match every expected context field, authenticate its own caller, verify current
state/version/lease/time, and enforce the operation's idempotency policy.

## Atomic idempotency and replay handling

The collector enforces database uniqueness on:

- `(log-id, caller-profile, idempotency-id)`;
- `(log-id, caller-profile, action-nonce)`;
- `(log-id, event-id)`;
- `(log-id, leaf-index)`.

For the first valid request, one serializable/locked transaction:

1. validates the exact event profile and authenticated caller;
2. reserves both replay keys and the next contiguous leaf index;
3. assigns collector-controlled identifiers and time;
4. deterministically encodes the event and computes its leaf hash;
5. prepares and signs the acceptance receipt;
6. durably stores the request digest, event bytes, receipt bytes, replay keys,
   and log position;
7. commits using the approved synchronous durability configuration;
8. only after successful commit returns the stored receipt and event bytes.

Signing before the commit is permitted only inside this sequence because no
receipt bytes are released until commit succeeds. A rollback discards the
unreleased result. There is no acknowledge-from-memory, asynchronous-queue, or
"audit later" success mode.

An identical retry with the same caller/idempotency ID and exact request digest
returns the original stored event and byte-identical receipt without adding a
leaf or extending validity. Reuse with a different digest, a second
idempotency ID with the same action nonce, or a second action nonce for a
one-time state/version loses the race and fails with one controlled result.

Parallel calls are tested across multiple connections and processes. An
application-side cache, in-memory lock, or pre-check is never authoritative.

## Merkle tree and RFC 9942 receipts

Leaves are ordered strictly by `leaf-index`. The tree uses exactly the RFC 9162
SHA-256 construction:

```text
leaf  = SHA-256(0x00 || event-bytes)
node  = SHA-256(0x01 || left-child-hash || right-child-hash)
empty = SHA-256(empty-byte-string)
```

The maximum merge delay is 60 seconds. The checkpoint signer seals a new tree
after at most 60 seconds from the first unmerged durable event or 1,024 new
events, whichever occurs first.

For each durable acceptance receipt, the service must make available within
the maximum merge delay:

- an RFC 9942 COSE Receipt of Inclusion using VDS `RFC9162_SHA256` (`vds = 1`),
  proof label `-1`, the exact leaf index, tree size, and inclusion path;
- the corresponding signed checkpoint;
- an RFC 9942 consistency receipt from the preceding trusted tree size when
  the tree grew.

The RFC 9942 receipt uses a detached root payload, protected `alg`, `kid`,
`vds`, and profile content type, and no unrecognized headers. Verification
returns one boolean only after both proof and signature checks succeed.

## Signed checkpoints and independent witness

The checkpoint signer uses a key distinct from every online receipt key. Its
deterministic payload is:

```text
audit-checkpoint-v1 = [
  version: 1,
  log-id: bstr .size 32,
  checkpoint-sequence: uint,
  tree-size: uint,
  root-hash: bstr .size 32,
  issued-at-ms: uint,
  previous-checkpoint-hash: bstr .size 32 / nil
]
```

The checkpoint is a tagged `COSE_Sign1` using Ed25519 and a dedicated protected
content type. `previous-checkpoint-hash` is SHA-256 over the preceding exact
signed checkpoint bytes. This link supplements, but does not replace, RFC 9162
consistency proofs.

When no event arrives, the signer emits a fresh heartbeat checkpoint over the
unchanged tree at least every five minutes. Each timestamp and checkpoint
sequence increases monotonically.

Before signing, the checkpoint signer independently reads the committed range,
recomputes deterministic event bytes, leaf hashes, tree root, contiguous
indices, and consistency from its last trusted checkpoint. Unknown versions,
missing/duplicate indices, changed bytes, rollback, fork, or time regression
stops signing.

The signed checkpoint and consistency evidence must be durably accepted by an
independent witness whose credentials and storage are unavailable to the Audit
Collector and report application. If no valid witnessed checkpoint exists for
more than seven minutes, the witness raises a controlled cessation alert. If
an accepted event lacks inclusion after 90 seconds, or a proof/checkpoint is
invalid, the condition alerts immediately.

If the witness cannot durably accept checkpoints, the collector stops issuing
new receipt-gated acceptance receipts no later than 90 seconds after the last
witnessed valid checkpoint. Existing receipts remain subject to their original
non-sliding expiry. There is no unwitnessed availability fallback.

The exact self-hosted alert transport remains independently OPEN. Before that
transport and its durable semantics are approved, this audit profile is not
production-authorized.

## Signing keys and rotation

- Online receipt-signing and checkpoint-signing keys are distinct Ed25519 key
  pairs and are purpose-separated from Django, TLS, service authentication,
  CAPTCHA, recovery verifier, DEK, export, and infrastructure keys.
- Private keys exist only in their approved signer trust domain. Application,
  database, audit-reader, and administrator credentials cannot export or use
  them.
- `kid` is the first 16 bytes of SHA-256 over the deterministic public COSE Key
  bytes and is always selected by the signer.
- Online receipt keys rotate at least every 90 days. A checkpoint-key-signed
  manifest fixes each key ID, public key, purpose, activation, retirement, and
  status. A retired receipt key verifies historical receipts but cannot sign.
- Checkpoint keys rotate at least annually. A rotation statement is signed by
  both old and new keys and must be accepted by the independent witness before
  the new key signs checkpoints.
- Loss or compromise fails closed. It never enables an unsigned, HMAC-shared,
  local-development, or previous-key fallback. Incident handling records the
  affected interval and requires an explicit new trust ceremony if continuity
  cannot be cryptographically proven.

The exact HSM/product, backup/recovery ceremony, operator quorum, and
cryptographic module validation remain deployment gates. Public verification
material is retained independently and does not confer signing capability.

## Retention and expiry authority

Event records and their exact receipt/proof material are retained for 365 days
from collector time. Signed checkpoints, consistency proofs, public-key
manifests, and witness verification outcomes are retained for 730 days so a
complete 365-day event window remains independently verifiable across rotation
and expiry boundaries.

Only the separately credentialed audit-retention process may expire eligible
records. It operates by collector time, cannot shorten policy, cannot delete a
checkpoint still needed to verify a retained event, and writes its own
controlled retention evidence. Application, operator, administrator,
checkpoint signer, and witness roles cannot request early expiry.

## Prohibited data

No request, event, receipt, tree entry, checkpoint, proof, alert, metric, trace,
or signer error may contain:

- report or Response Note text;
- attachment bytes, embedded metadata, or original filename;
- Recovery Secret, recovery verifier/tag, CAPTCHA answer, or attempt credential;
- cryptographic key material;
- arbitrary reporter or operator free text;
- reporter IP address, User-Agent, headers, cookies, URL/query values, or body;
- raw exceptions or parser output;
- a plain digest that enables confirmation guessing of low-entropy protected
  content.

Schemas reject unknown fields at the boundary. Logs may contain only a
separate controlled service event code and bounded timing result; they do not
copy audit request/receipt objects wholesale.

## Failure behavior

| Failure | Required result |
|---|---|
| Caller identity or event profile mismatch | Reject; no append and no receipt |
| Unknown/non-deterministic CBOR or wrong length/type | Reject with one controlled result |
| Duplicate idempotency with identical digest | Return original byte-identical event/receipt; no new leaf or expiry |
| Duplicate idempotency with different digest | Reject and controlled security alert; reveal no supplied value |
| Duplicate action nonce or stale state/version/lease | Reject; no second protected effect |
| Store, signer, trusted clock, or durability unavailable | No receipt; protected action fails closed |
| Commit fails after signing but before release | Discard unreleased bytes; retry through the same idempotency context |
| Receipt signature/hash/context/expiry invalid | Protected service denies action |
| Inclusion exceeds 60-second merge delay | Stop new protected receipts by 90 seconds and alert |
| Missing/inconsistent/forked checkpoint | Stop signing/issuing, preserve evidence, and alert |
| Witness unavailable | Stop new protected receipts within 90 seconds; no local witness fallback |
| Outcome append fails after protected effect | Never falsify success; retry the truthful phase and raise controlled operational state |
| Receipt/checkpoint key loss or compromise | Fail closed; no weaker signer or unsigned mode |
| Unknown event state after irreversible key destruction | Never recreate a key or reopen content; resume only the evidenced forward workflow |

## Required tests before enablement

At minimum, release-blocking tests must prove:

- RFC 8949 deterministic encoding vectors and rejection of alternate encodings,
  types, sizes, versions, registries, and trailing fields;
- RFC 8032/COSE EdDSA vectors, exact protected headers, curve/key checks, and
  rejection of altered payload, signature, key ID, algorithm, or content type;
- RFC 9162 tree-root, inclusion, and consistency vectors plus RFC 9942 COSE
  Receipt verification;
- no valid receipt is returned before durable transaction commit;
- crash injection before and after signing/commit/reply reaches only the
  documented outcome;
- 20–100 synchronized identical/different retries across multiple PostgreSQL
  connections and processes produce one leaf and one byte-identical receipt;
- reused idempotency IDs, reused nonces, stale state versions, stale lease
  generations, wrong actors/objects/operations, and expired receipts fail closed;
- receipt verification alone cannot authorize without authenticated caller,
  current server state, and every other mandatory control;
- every receipt-gated event profile requires exactly its allowed non-null fields
  and rejects forbidden fields;
- REQUESTED/AUTHORIZED/COMPLETED/FAILED phases never claim an unperformed effect;
- every accepted event receives inclusion inside 60 seconds and consistency
  from the previous trusted checkpoint;
- mutation, middle deletion, duplicate index, suffix truncation, fork,
  rollback, checkpoint-key substitution, and audit cessation are detected;
- idle five-minute heartbeats and seven-minute witness liveness alert work;
- witness failure stops new protected receipts within 90 seconds;
- key rotations and 365/730-day retention preserve verification without
  granting signing or early-expiry authority;
- no prohibited data reaches audit, logs, alerts, metrics, traces, exceptions,
  checkpoints, receipts, or proofs.

SQLite, ordinary Django `TestCase`, one process, or an in-memory collector is
not sufficient for concurrency, durability, or release acceptance.

## Inert Stage A audit-retention planning record

The metadata-only Stage A represents the exact retention minima in
`report_lifecycle/audit_retention.py`. The pure planner accepts only internal
retention/evidence UUIDs, a closed evidence class, trusted collector timestamps,
and a strict verification-dependency flag. It calculates 365 times 24 elapsed
hours for event/receipt/proof material and 730 times 24 elapsed hours for signed
checkpoint, consistency, public-key-manifest, and witness evidence.

Before the minimum boundary the evidence remains retained. At or after that
boundary, any required verification dependency still retains it; otherwise the
result says only that expiry review is due. Every capability flag is false and
the executor is deliberately unavailable. No audit row, receipt, proof,
checkpoint, manifest, or witness result is read, persisted, exposed, or deleted.
The isolated credential, daily job, dependency proof, controlled retention
batch record, witness interface, legal approval, independent review, and all
Audit Service/production gates remain OPEN.

The following source-policy slice parses but never imports or executes
`audit_retention.py`. It fixes the exact target/import/member set, both closed
enums, immutable snapshot and plan fields, five false capability flags, allowed
calls and raises, protected bindings, and always-unavailable executor. Database
expiry, scheduler, witness, network, I/O, logging, mutation, dynamic syntax,
receipt/content/key fields, and executable executor changes fail closed.

Passing is static source conformance only. It proves no trusted Audit Collector
clock, isolated identity, dependency graph, persistence, controlled retention
record, witness evidence, legal approval, or production Audit Service behavior.

## Recorded project-owner decision

On 2026-08-25 the project owner approved all five visible choices:

1. deterministic CBOR, COSE Sign1/Ed25519, two signing-key roles, and the exact
   version-1 event/acceptance-claim schemas;
2. the idempotency/nonces policy and the proposed per-operation non-sliding
   authorization lifetimes;
3. the RFC 9162 SHA-256 tree, 60-second/1,024-event merge rule, and RFC 9942
   inclusion/consistency receipts;
4. five-minute heartbeat checkpoints, seven-minute witness alerting, and
   fail-closed cessation of new protected receipts within 90 seconds;
5. 90-day receipt-key rotation, annual checkpoint-key rotation, dual-signed
   transition, and 365-day event / 730-day verification-evidence retention.

Independent cryptographic/protocol review remains a release gate. Production
also remains blocked by the Audit Service topology,
signer/HSM, service authentication, PostgreSQL durability/concurrency, alert
transport, clock, deployment, and every protected operation's own gates.

## External design references

- [RFC 8949 — Concise Binary Object Representation (CBOR)](https://www.rfc-editor.org/rfc/rfc8949.html)
- [RFC 9052 — CBOR Object Signing and Encryption (COSE): Structures](https://www.rfc-editor.org/rfc/rfc9052.html)
- [RFC 9053 — COSE: Initial Algorithms](https://www.rfc-editor.org/rfc/rfc9053.html)
- [RFC 8032 — Edwards-Curve Digital Signature Algorithm](https://www.rfc-editor.org/rfc/rfc8032.html)
- [RFC 9162 — Certificate Transparency Version 2.0](https://www.rfc-editor.org/rfc/rfc9162.html)
- [RFC 9942 — COSE Receipts](https://www.rfc-editor.org/rfc/rfc9942.html)
- [FIPS 180-4 — Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)
- [FIPS 186-5 — Digital Signature Standard](https://csrc.nist.gov/pubs/fips/186-5/final)
