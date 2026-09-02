# Security interface placeholders

This package contains only deny-by-default placeholders for security service
families whose concrete construction is still blocked by
`docs/12_OPEN_SECURITY_DECISIONS.md`.

The public method names identify capability families already approved in
`docs/19_SECURITY_SERVICE_INTERFACES.md`. `audit_descriptors.py` additionally
models only the closed event/actor names, exact replay-field lengths, and
acceptance-claim lifetimes already fixed by `docs/23`. It intentionally does
not define the still-incomplete per-event request profiles, wire encodings,
credentials, cryptographic verification, or deployment topology.

`alert_descriptors.py` models only the ten fixed alert types and severities,
delivery-state names, actor/operation identifier shapes, acceptance response,
and acknowledgement pairing already exact in `docs/31`. The complete submit
request remains unavailable because the formal source-profile, object-kind,
condition-code, and per-type combination registries are not fully enumerated.

Every call raises the same controlled `SecurityControlUnavailable` error. The
placeholders:

- never return a success value;
- never store plaintext or keys;
- never log caller input;
- never provide a development bypass;
- are not registered as a Django application;
- must not be replaced until the specific OPEN gate is approved and its
  negative/failure tests exist.

A non-executing source policy additionally locks the controlled error registry
and every unavailable adapter to their exact fail-closed executable AST. It
rejects success returns, fallback services, new public methods, input-bearing
errors, logging, and other side effects without importing or executing either
target. Passing this policy does not prove a real service boundary.

A structurally valid acceptance-claims object is not a verified receipt and
always reports that it cannot authorize a protected action. CBOR encoding,
COSE parsing/signature verification, event append, durable commit, receipt
release, and all protected consumers remain absent. The context-dependent
`REPORT_KEY_DESTROYED` authorization lifetime is rejected until its exact
operation profile is closed rather than guessed.

A non-executing source policy additionally locks the complete executable AST of
`audit_descriptors.py` to this exact inert profile. It rejects registry, field,
validator, lifetime, success-return, import, dynamic, and side-effect changes
without importing or executing the module. Passing is only source-conformance
evidence; it does not encode or verify an audit artifact or authorize an action.

Likewise, a structurally valid alert acceptance response proves neither a
durable database/queue commit nor SMTP delivery and never authorizes a
protected action. There is no Alert Service client, outbox, persistence,
transport, acknowledgement mutation, or development success adapter.

The alert descriptor's complete executable AST is also locked by a
non-executing source policy. Registry, field, validator, false durability or
authorization result, import, dynamic, and side-effect changes fail closed.
Passing does not prove durable acceptance, delivery, acknowledgement, or an
Alert Service boundary.

`captcha_descriptors.py` models only the owner-approved version-1
no-JavaScript CAPTCHA protocol metadata: 16-byte challenge identifiers encoded
as 22-character unpadded base64url text, six-character uppercase answers from
the approved 32-symbol alphabet, 16-byte anonymous form scope shape, five-minute
non-sliding expiry, 15-minute cleanup horizon, PNG bounds, global purpose/action
token-bucket limits, and the open production gates. It returns content-free
shape evidence only. It does not generate challenges, render image/audio,
persist challenge records, compare answers, use request/IP/User-Agent/device
data, expose endpoints, call a Challenge Service, or authorize operations.

The CAPTCHA descriptor source is also locked by a non-executing exact-AST
policy. Passing proves only reviewed source shape and closes no Pillow/font,
audio/accessibility, PostgreSQL concurrency, Challenge Service, gateway,
endpoint, deployment, or production gate.

`request_admission_descriptors.py` models only the owner-approved version-1
request and multipart admission metadata: the 21 MiB encoded-body ceiling,
5 MiB per-file and 20 MiB aggregate-file ceilings, text/control/header/part
limits, closed POST multipart profile, file-slot order, bounded streaming
memory limits, and header/body deadlines. It does not parse HTTP or multipart
bodies, install Django upload handlers, read file bytes, expose filenames,
create sandbox jobs, persist plaintext, log request material, or accept a
submission.

The request-admission descriptor source is locked by a non-executing exact-AST
policy. Passing proves only reviewed source shape and closes no proxy, Django
upload-handler, sandbox, CSRF, CAPTCHA, audit, Key Service, no-spool,
request-smuggling, endpoint, deployment, or production gate.

`attachment_admission_descriptors.py` models only the owner-approved common
version-1 attachment admission metadata: one PDF slot, three image slots,
5 MiB per-file limit, accepted kind/slot/extension registries, the transient
defense-in-depth filename shape, and the explicit denial that client MIME,
Content-Disposition, paths, extensions, magic bytes, parser warnings, or partial
success can authorize acceptance. It does not inspect file bytes, parse formats,
create sandbox jobs, persist originals, retain filenames, log request material,
or authorize uploads.

The attachment-admission descriptor source is locked by a non-executing
exact-AST policy. Passing proves only reviewed source shape and closes no
JPEG/PNG/PDF parser, renderer, sandbox, encryption, safe-view, endpoint,
deployment, or production gate.

`safe_view_descriptors.py` models only the owner-approved operator safe-view
metadata: PNG-only output, 8-bit sRGB profile, 144 DPI PDF rendering metadata,
4,096-pixel dimensions, 16 MiB per-output and 128 MiB aggregate-output limits,
50,000,000 rendered-pixel limit, no-store/nosniff image response headers,
POST initiation, required operator/state/lease/object bindings, and ordinary
original-download denial. It does not decrypt attachments, render files,
validate PNG bytes, call a sandbox, persist output, serve responses, inspect
leases, or authorize operator access.

The safe-view descriptor source is locked by a non-executing exact-AST policy.
Passing proves only reviewed source shape and closes no decrypt, renderer,
restricted-PNG verifier, sandbox, lease, response, endpoint, deployment, or
production gate.

`file_sandbox_descriptors.py` models only the owner-approved sandbox isolation
metadata: Firecracker reference, one fresh microVM per job, vCPU/RAM/process/
file-descriptor/time limits, authenticated vsock transport shape, read-only
measured root, guest RAM/tmpfs-only workspace, one-time job capability, no
production credentials, no NIC/MMDS/DNS/shell/SSH/swap/snapshot/core dump, and
no reusable writable storage. It does not boot microVMs, execute parsers, open
files, create jobs, exchange vsock messages, inspect attachments, persist
plaintext, or authorize file processing.

The file-sandbox descriptor source is locked by a non-executing exact-AST
policy. Passing proves only reviewed source shape and closes no Firecracker,
jailer, kernel/rootfs, broker, vsock, parser, renderer, sandbox execution,
deployment, or production gate.

`step_up_descriptors.py` models only the report-bound v1 UUID/counter context,
the exact 120-second lifetime, ES256/EdDSA algorithm registry, binding purpose
and key epoch, and an unused-only Stage A state. It deliberately contains no
challenge, POST handle, credential row, artifact bytes, HMAC output, operation,
report-state, or artifact-kind value. A structurally valid component set does
not verify WebAuthn or an artifact binding and authorizes nothing.

A non-executing exact-AST policy locks this report-bound v1 source profile.
Identifier/counter fields, registries, timing, unused state, validators, false
verification/authorization results, imports, and absence of dynamic/effectful
behavior cannot change silently. Passing proves no WebAuthn, binding, session,
persistence, consumption, or protected authorization.

`administrative_step_up_descriptors.py` models only the approved version-2
foundations that are already exact without inventing an operation profile:
16-byte authorization/administrator/session/device identifiers, binding purpose
and key epoch, the non-sliding 120-second lifetime, and an unused-only Stage A
state. Operation, target kind/ID, artifact kind/binding, credential-row ID,
challenge, opaque handle, persistence, consumption, and actor-role-specific
flood profiles remain absent. Structural validity verifies nothing and
authorizes neither an administrative action nor flood deletion.

The non-executing descriptor-source policy locks that exact inert source shape,
including its imports, constants, immutable classes, validators, and closed
call profile. Passing the policy is source-conformance evidence only; it is not
authentication, WebAuthn, session, persistence, concurrency, or production
proof.

`recovery_descriptors.py` validates only the strict structural shape of the
owner-approved recovery credentials: a 16-byte, 26-character uppercase
unpadded RFC 4648 Base32 Ticket ID and a 32-byte, 43-character unpadded
base64url Recovery Secret. Successful validation returns content-free shape
evidence only. It does not retain the supplied credential text or decoded
bytes, generate credentials, compute an HMAC/verifier, store a plaintext
secret, perform lookup, authorize recovery, expose an endpoint, or call a
service.

The recovery descriptor source is also locked by a non-executing exact-AST
policy. Imports, constants, immutable classes, validators, false capability
results, and absence of generation/verifier/storage/authorization behavior
cannot change silently. Passing is only source-conformance evidence and closes
no recovery, cryptographic-review, persistence, external-service, or production
gate.

`recovery_key_lifecycle_descriptors.py` validates only the static verifier-key
lifecycle profile approved in `docs/21`: a 32-byte Recovery Verifier key,
active-for-creation, retired-verify-only, and destroyed-after-no-eligible-
references states, explicit separation from application, report, response,
audit, export, TLS, CAPTCHA, CSRF, session, and service-authentication keys,
forbidden source/settings/database/log/audit/browser/response locations, and
fail-closed lifecycle requirements. It does not generate, store, select,
rotate, destroy, or rewrite keys, call a Key Service, authorize Response-DEK
use, expose endpoints, or authorize recovery.

The recovery key lifecycle descriptor source is locked by a non-executing
exact-AST policy. Passing proves only reviewed source shape; it is not a key
inventory, rotation executor, verifier service, Response-DEK authorization
path, incident procedure, persistence layer, endpoint behavior, or production
evidence.

`recovery_verification_descriptors.py` validates only the static verifier
verification semantics approved in `docs/21`: full-length HMAC-SHA-256,
constant-time full-tag comparison, boolean-only result, HMAC success as
necessary but not sufficient, canonical input requirements, unknown-ticket
dummy verification, generic external non-success behavior, timing-distribution
test requirement, and no perfect-indistinguishability claim. It does not
compute HMACs, compare tags, execute dummy verification, return expected tags
or partial-match details, read response state, validate CAPTCHA, call a Key
Service, authorize Response-DEK use, log credentials, expose endpoints, or
authorize recovery.

The recovery verification descriptor source is locked by a non-executing
exact-AST policy. Passing proves only reviewed source shape; it is not verifier
construction, HMAC execution, timing proof, recovery workflow authorization,
Response-DEK authorization, endpoint behavior, or production evidence.

`report_crypto_descriptors.py` validates only the static version-1 original
report crypto profile already fixed in `docs/26`: XChaCha20-Poly1305-IETF
combined-mode metadata, 32-byte Report-DEK and object-subkey sizes, fixed
report-text and attachment frame sizes, fixed ciphertext/tag sizes, immutable
context-size shapes, AAD/KDF purposes, object-kind/slot metadata, and the
seven allowlisted Report-DEK operation names. It never receives or retains
report text, attachment bytes, ciphertext bytes, nonce bytes, AAD bytes,
Report-DEK/subkey material, key-handle values, operator authorization, audit
receipts, or state rows.

The report crypto descriptor source is locked by a non-executing exact-AST
policy. Passing proves only reviewed source shape; it is not canonicalization,
framing, HKDF, CBOR, encryption, decryption, Key Service behavior, sandbox
streaming, persistence, endpoint behavior, authorization, deletion,
restoration, deployment, or production evidence.

`report_schema_descriptors.py` validates only the ordered metadata schema for
the approved original-report AAD and ciphertext envelope fields. It records
field names, primitive categories, fixed byte sizes, public constant values,
allowed public object kinds, allowed public object slots, and allowed public
frame/ciphertext sizes only. It does not encode or parse CBOR, retain
report/attempt/object IDs, retain key handles, retain nonces or ciphertext,
call a service, inspect state, stream attachments, persist data, expose an
endpoint, or authorize report use.

The report schema descriptor source is locked by a non-executing exact-AST
policy. Passing proves only reviewed source shape; it is not deterministic
CBOR, context binding, ciphertext handling, Key Service behavior, sandbox
streaming, persistence, endpoint behavior, authorization, or production
evidence.

`report_text_descriptors.py` performs only transient validation for the
approved original-report text profile: Unicode scalar values, NUL rejection,
unpaired-surrogate rejection, CRLF/CR-to-LF profile, NFC normalization rule,
strict UTF-8 limits, 5,000-scalar limit, 20,000-byte limit, and the
owner-approved rule that only the canonical UTF-8 representation is the
authoritative original. Successful validation returns only the fixed profile
descriptor and never returns or stores the supplied text, normalized text,
canonical bytes, digest, frame, ciphertext, submission ID, or state.

The report text descriptor source is locked by a non-executing exact-AST
policy. Passing proves only reviewed source shape; it is not browser/wire
discard enforcement, canonical byte freezing, frame construction, encryption,
submission staging, endpoint behavior, logging proof, or production evidence.

`report_frame_descriptors.py` validates only the ordered metadata layout for
the approved original-report plaintext frames. It records the version byte,
uint32/uint64 big-endian length fields, canonical UTF-8 text payload marker,
accepted-original attachment byte marker, public PDF/JPEG/PNG kind codes,
total fixed frame sizes, and zero-padding requirements. It does not receive
plaintext bytes, construct frames, parse frames, validate padding bytes,
inspect attachments, encrypt, decrypt, persist content, expose endpoints, or
authorize submission.

The report frame descriptor source is locked by a non-executing exact-AST
policy. Passing proves only reviewed source shape; it is not frame
construction, frame parsing, padding validation, attachment validation,
encryption, storage, endpoint behavior, or production evidence.

`submission_audit_descriptors.py` validates only the static audit profile for
the approved submission acceptance sequence in `docs/20`. It records the
ordered `SUBMISSION_ACCEPTANCE_REQUESTED`, `SUBMISSION_RECEIVED`, and
`SUBMISSION_ACCEPTANCE_FAILED` phase names, their required timing labels,
authorization windows, durable-receipt requirement flags, and the closed
allowed/forbidden payload-field registries. It does not append audit events,
create or verify receipts, inspect attempt state, call the Audit Service,
create report keys, persist submission metadata, or authorize a submission.

The submission-audit descriptor source is locked by a non-executing exact-AST
policy. Passing proves only reviewed source shape; it is not audit append,
durable receipt creation, receipt verification, attempt-state inspection,
Audit Service behavior, persistence, Key Service behavior, endpoint behavior,
or production evidence.

`submission_acceptance_checkpoint_descriptors.py` validates only the static
Phase 0-6 checkpoint profile approved in `docs/20`. It records the ordered
submission acceptance phase labels, checkpoint labels, exact prerequisite
metadata, and forbidden runtime capability categories. It does not parse
requests, validate credentials, claim attempts, append audit events, verify
receipts, call the Key Service, encrypt, persist records, render responses,
run reconciliation, expose endpoints, or authorize submission.

The submission acceptance checkpoint descriptor source is locked by a
non-executing exact-AST policy. Passing proves only reviewed source shape; it
is not a request handler, acceptance coordinator, audit/client implementation,
Key Service adapter, database transaction, response renderer, reconciler,
endpoint behavior, or production evidence.

`submission_attempt_credential_descriptors.py` validates only the static
attempt-credential policy approved in `docs/20`: single-use semantics, the
two-hour non-sliding pre-claim lifetime, POST body and protected same-site
cookie transport labels, URL/query/referrer/header-log denials, independence
from report content, Ticket ID, Recovery Secret, IP address, User-Agent,
reporter accounts, and device fingerprints, plus minimum verifier/index,
database uniqueness, and row/state-version metadata. It does not generate or
verify credentials, persist credential material, install cookies, inspect
requests, claim attempts, call services, expose endpoints, or authorize
submission/report access.

The attempt-credential descriptor source is locked by a non-executing
exact-AST policy. Passing proves only reviewed source shape; it is not
credential generation, verifier construction, cookie binding, request handling,
database uniqueness enforcement, endpoint behavior, submission authorization,
or production evidence.

`submission_reconciliation_descriptors.py` validates only the static
reconciliation profile approved in `docs/20`: maximum scan interval, progress
deadline, cleanup retry cap, persistent-cleanup-alert threshold, candidate
attempt states, terminal outcomes, action names, alert type, and content-free
allowed/forbidden payload metadata. It does not scan report content, decrypt
plaintext, create credentials, append audit events, verify receipts, call the
Audit/Key/Alert services, delete ciphertext, mutate attempts, schedule jobs, or
authorize submission.

The submission-reconciliation descriptor source is locked by a non-executing
exact-AST policy. Passing proves only reviewed source shape; it is not a crash
reconciler, scheduler, cleanup executor, service adapter, state transition,
deletion operation, endpoint behavior, or production evidence.

`submission_retry_descriptors.py` validates only the static duplicate/retry
outcome profile approved in `docs/20`: allowed retry source labels, required
one-database-winner and no-second-pipeline outcomes, controlled indeterminate
response behavior, no credential redisplay, and forbidden signal categories.
It does not parse requests, verify attempt credentials, claim attempts, inspect
database state, create reports or Report-DEKs, append audit events, redisplay
credentials, expose status oracles, call services, expose endpoints, or
authorize submission.

The submission retry descriptor source is locked by a non-executing exact-AST
policy. Passing proves only reviewed source shape; it is not duplicate
detection, retry handling, credential verification, database claiming,
pipeline suppression, response rendering, endpoint behavior, or production
evidence.

`submission_credential_response_descriptors.py` validates only the static
one-time credential-response and lost-response policy approved in `docs/20`.
It records the one live post-acceptance display opportunity, the controlled
indeterminate retry result, the public field names that may appear only in that
live response, and the forbidden persistence categories: plaintext Recovery
Secret, redisplay state, replacement credential state, `credentials_delivered`
claims, content hashing/deduplication, request headers, and raw errors. It
does not generate credentials, persist secrets, render responses, inspect
requests, mutate attempts, call services, expose endpoints, or authorize
recovery/submission.

The credential-response descriptor source is locked by a non-executing
exact-AST policy. Passing proves only reviewed source shape; it is not
credential generation, verifier construction, response rendering, request
handling, recovery authorization, submission authorization, or production
evidence.

`submission_failure_descriptors.py` validates only the static failure matrix
approved in `docs/20`. It records the exact failure boundary labels, required
result labels, and content-free/fail-closed flags for unsupported requests,
parallel copies, audit unavailability, validation/sandbox uncertainty, Key
Service failure, staging failure, metadata failure, crash/retry conditions,
cleanup failure, and unknown state/version/receipt inputs. It does not handle
requests, start submission pipelines, call services, write storage, create
keys, persist plaintext, append audit events, mutate state, return
credentials, expose endpoints, or authorize submission.

The submission failure descriptor source is locked by a non-executing
exact-AST policy. Passing proves only reviewed source shape; it is not
failure handling, rollback, cleanup execution, retry processing, audit/client
behavior, response rendering, endpoint behavior, or production evidence.

`submission_idempotency_descriptors.py` validates only the static
concurrency/idempotency invariant profile approved in `docs/20`. It records
the exact sequential-retry, synchronized-parallel-copy, multi-process,
reconciliation, stale-version, response-loss, crash-injection, cleanup, and
logging scenarios, plus the required invariants and forbidden runtime
capability categories. It does not run parallel requests, inspect attempts,
lock rows, write storage, create keys, append audit events, reconcile
artifacts, log inputs, expose endpoints, or authorize submission.

The submission idempotency descriptor source is locked by a non-executing
exact-AST policy. Passing proves only reviewed source shape; it is not a
concurrency test runner, database lock implementation, service adapter,
artifact reconciler, logging pipeline, endpoint behavior, or production
evidence.

`recovery_failure_descriptors.py` validates only the static failure-behavior
profile approved in `docs/21`. It records the exact random-source, collision,
encoding, verifier/key, unknown version/key, HMAC mismatch, unavailable/
expired/destroyed response, concurrent first-read, Response-DEK expiry, and
credential logging/telemetry failure labels, their required generic/fail-closed
results, and forbidden runtime capabilities. It does not generate randomness,
decode credentials, call a verifier, compare HMAC tags, read response state,
call the Key Service, log credentials, expose endpoints, or authorize recovery.

The recovery failure descriptor source is locked by a non-executing exact-AST
policy. Passing proves only reviewed source shape; it is not random
generation, verifier construction, HMAC verification, recovery workflow
authorization, first-read mutation, Key Service behavior, endpoint behavior, or
production evidence.

The recovery key lifecycle descriptor source is locked by a non-executing
exact-AST policy. Passing proves only reviewed source shape; it is not key
generation, secret storage, key selection, rotation execution, destruction,
verifier-record rewriting, Key Service behavior, Response-DEK authorization,
endpoint behavior, or production evidence.

The recovery verification descriptor source is locked by a non-executing
exact-AST policy. Passing proves only reviewed source shape; it is not HMAC
computation, constant-time comparison implementation, dummy verification,
timing-distribution evidence, response-state access, CAPTCHA validation, Key
Service behavior, Response-DEK authorization, endpoint behavior, or production
evidence.

`response_crypto_descriptors.py` validates only the static version-1 Response
Note crypto profile already fixed in `docs/24`: XChaCha20-Poly1305-IETF
combined-mode metadata, fixed plaintext-frame and ciphertext/tag sizes,
immutable context-size shapes, AAD purpose, and the six allowlisted
Response-DEK operation names. It never receives or retains Response Note text,
ciphertext bytes, nonce bytes, AAD bytes, Response-DEK material, key-handle
values, recovery authorization, audit receipts, or state rows.

The response crypto descriptor source is locked by a non-executing exact-AST
policy. Passing proves only reviewed source shape; it is not canonicalization,
CBOR, encryption, decryption, Key Service behavior, verifier behavior,
persistence, recovery authorization, endpoint behavior, or production evidence.

`response_text_descriptors.py` performs only transient validation for the
approved Response Note text profile: Unicode scalar values, NUL rejection,
LF line-ending profile, NFC normalization rule, strict UTF-8 limits, plain text,
and conservative no-HTML/no-link markers. Successful validation returns only
the fixed profile descriptor and never returns or stores the submitted text,
normalized text, canonical bytes, digest, preview, draft, frame, or state.

The response text descriptor source is locked by a non-executing exact-AST
policy. Passing proves only reviewed source shape; it is not final preview,
canonical byte freezing, artifact digesting, step-up binding, persistence,
finalization, response staging, endpoint behavior, or production evidence.

`response_schema_descriptors.py` validates only the ordered metadata schema for
the approved Response Note AAD and ciphertext envelope fields. It records field
names, primitive categories, fixed byte sizes, and public constant values only.
It does not encode or parse CBOR, retain report/response/finalization IDs,
retain key handles, retain nonces or ciphertext, call a service, inspect state,
or authorize response use.

The response schema descriptor source is locked by a non-executing exact-AST
policy. Passing proves only reviewed source shape; it is not deterministic
CBOR, envelope parsing, cryptographic authentication, persistence, Key Service
behavior, recovery behavior, endpoint behavior, or production evidence.

The package initializer is also locked by a non-executing exact-AST policy so
its reviewed re-export surface cannot gain a production service, side effect,
dynamic behavior, or widened public capability without an explicit policy
update. Passing this initializer policy is source-conformance evidence only.
