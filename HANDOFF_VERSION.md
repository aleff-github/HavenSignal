# Handoff Version

Version: 0.3
Prepared: 2026-08-26

This handoff consolidates:

- the completed project security questionnaire;
- later clarifications made after the questionnaire;
- the current Python/Django implementation direction;
- unresolved security decisions that must not be silently guessed by Codex.

Version 0.2 additionally incorporates:

- non-resurrectable live-replicated Report-DEK/Response-DEK policy;
- explicit Application Administrator and Infrastructure / Key Custodian trust roles;
- Reporter Gateway capability restrictions;
- idempotent `FINALIZING` protocol;
- durable pre-action audit receipts and truncation detection;
- protected operator notes outside permanent audit;
- persisted lease generation/fencing;
- action-bound step-up authorization;
- explicit requirement IDs and traceability for recovery, response, export, CAPTCHA, file sandbox/CDR, roles, keys, alerts, and finalization.

Version 0.3 additionally incorporates exact proposals for:

- WebAuthn MFA, action-bound step-up, and credential lifecycle;
- original-report cryptography and Key Service destructive acceptance;
- Emergency Export packaging, encryption, signature, and delivery;
- hostile file admission, disposable sandboxing, and bounded multipart input;
- durable content-free administrator alerts;
- Response Note retention and receipt-gated deletion, including exceptional
  content-blind flood handling;
- physically and operationally separated role workstations and access paths;
- one consolidated, non-authorizing pre-code owner gate and a narrow inert
  Stage A implementation boundary.

No production-capable security workflow is enabled. The included Django code
is an inert scaffold plus deny-by-default interfaces and metadata-only domain
structures whose protected integrations remain gated.

The project owner approved `docs/25` through `docs/34` on 2026-08-26 and
authorized only the inert metadata-only Stage A. All independent, product,
production-equivalent, legal, operational, and release gates remain in force.

The first Stage A slice now includes the inert `report_lifecycle` metadata
schema, pure transition/lease planners, database constraints, and negative
tests. It exposes no protected endpoint or content-handling capability.

The second Stage A slice adds immutable cross-object binding validators and a
PostgreSQL capability gate whose persistence entry point always fails closed.
No SQLite or mocked-backend result can enable metadata writes.

The third Stage A slice adds immutable, content-free audit-v1 registry/replay/
acceptance-claim descriptors and strict structural validation. It contains no
CBOR/COSE implementation, signature verification, audit append, durable
receipt, or authorization capability; incomplete context profiles fail closed.

The fourth Stage A slice adds immutable, content-free alert-v1 registry and
component descriptors. Structural acceptance proves no durable commit,
delivery, acknowledgement, or authorization; all Alert Service integrations
and incomplete source/object/condition profiles remain unavailable.

The fifth Stage A slice adds report-bound step-up-v1 metadata components and
strict 120-second timing/algorithm validation while excluding challenges,
handles, credentials, artifact/HMAC bytes, consumed state, persistence, and all
authentication or authorization capability.

The sixth Stage A slice adds non-executing AST import allowlists for the inert
Reporter Gateway and root URL configuration. The checks make new source-level
dependency edges explicit but do not claim runtime or deployment isolation.

The seventh Stage A slice adds non-executing static policies for the inert
Django settings, single reporter-home route, passive template subset, and
no-resource-loading CSS. It adds controlled fail-closed abuse tests but no
browser, runtime, protected workflow, or production capability.

The eighth Stage A slice adds a test-only, UUID-only plan for six future
PostgreSQL metadata-concurrency scenarios with 20–100 contenders. The runner
always remains unavailable, adds no driver or credentials, writes no rows, and
is explicitly not PostgreSQL concurrency or release evidence.

The ninth Stage A slice adds non-executing conformance checks for the exact
initial lifecycle migration plus a dry Django drift test. It makes new
migrations, fields, constructors, imports, dynamic/data/SQL operations, and
model drift explicit without changing or executing production database work.

The tenth Stage A slice adds the exact inert finalization sequence as immutable,
content-free, non-authorizing and non-persisting edges, retaining and strictly
checking the existing operation idempotency UUID. Its executor always fails
closed; no receipt, staging, key, publication, cleanup, or resume capability is
implemented.

The eleventh Stage A slice adds the exact OPEN-only operator-deletion sequence
as immutable, content-free, non-authorizing, non-persisting, and explicitly
non-destructive edges. Its executor always fails closed; no reason or protected
note, CAPTCHA, step-up, receipt, database transition, key destruction, recovery
invalidation, cleanup, or resume capability is implemented.

The twelfth Stage A slice adds non-executing AST purity checks for the inert
finalization and operator-deletion modules. Exact imports, members,
UUID/counter/checkpoint-only plans, false capability flags, closed calls, and
always-unavailable executors are required. The scanner imports and executes no
target and provides no runtime or protected-workflow authority.

The thirteenth Stage A slice adds immutable, metadata-only Response Note
retention planning for the exact 90-times-24-hour unread boundary and validation
of one stored non-sliding 72-hour window after a pre-deadline first read. It
never proposes a first read. Exact-boundary expiry wins, every capability flag
is false, and the executor always fails closed. No persistence, recovery,
decryption, destruction, cleanup, endpoint, external-service call, or
production authority is introduced.

The fourteenth Stage A slice extends the non-executing AST purity policy to the
retention module. Exact imports/members, immutable content-free snapshot and
plan fields, false capability flags, closed calls, protected binding names, and
the always-unavailable executor are required. The scanner never imports or
executes the target and provides no recovery, expiry, persistence, decryption,
destruction, cleanup, or production authority.

The fifteenth Stage A slice adds immutable UUID/counter/timestamp-only planning
for the exact ciphertext-cleanup retry tiers, 10% jitter ceiling, one-minute
reconciler ceiling, and 15-minute persistent-failure alert boundary. It chooses
no jitter, schedules/persists nothing, submits no alert, calls no service, and
authorizes no deletion. Its executor always fails closed; no cleanup runtime or
production evidence is introduced.

The sixteenth Stage A slice extends the non-executing AST purity policy to the
cleanup planner. Exact imports/timing members, closed enums, immutable
content-free snapshot/plan fields, false capability flags, closed calls,
protected bindings, and the always-unavailable executor are required. The
scanner never imports or executes the target and provides no scheduling, alert,
storage, deletion, cleanup, or production authority.

The seventeenth Stage A slice adds immutable UUID/timestamp-only terminal
application metadata retention planning. Incomplete cleanup is retained with no
removal time; durable cleanup confirmation starts exactly 30 times 24 elapsed
hours in UTC, after which only a removal review is marked due. All capability
flags are false and the executor always fails closed. No Ticket ID lookup or
metadata deletion, persistence, job, service call, recovery change, Key Service
tombstone handling, or production authority is introduced.

The eighteenth Stage A slice extends the non-executing AST purity policy to the
terminal-metadata retention planner. Exact imports/members, the closed
disposition enum, immutable content-free snapshot/plan fields, five false
capability flags, closed calls, protected bindings, and the always-unavailable
executor are required. The scanner never imports or executes the target and
provides no database deletion, retention job, recovery change, Key Service
tombstone handling, or production authority.

The nineteenth Stage A slice adds immutable UUID/class/dependency/timestamp-only
audit-retention planning. It fixes exact 365-times-24-hour event/receipt/proof
and 730-times-24-hour checkpoint/consistency/key-manifest/witness minima from
trusted collector time, while a required verification dependency retains longer.
Every capability flag is false and the executor always fails closed. No audit
expiry, retention batch, isolated credential, witness output, database write,
service integration, legal approval, or production authority is introduced.

The twentieth Stage A slice extends the non-executing AST purity policy to the
audit-retention planner. Exact imports/members, both closed enums, immutable
content-free snapshot/plan fields, five false capability flags, closed calls,
protected bindings, and the always-unavailable executor are required. The
scanner never imports or executes the target and provides no audit expiry,
trusted-clock proof, isolated credential, retention batch, witness integration,
legal approval, or production authority.

The twenty-first Stage A slice adds immutable administrative step-up-v2
foundations for exact internal identity shapes, binding-purpose/key-epoch
metadata, the 120-second non-sliding lifetime, and unused-only state. It omits
operation/target/artifact profiles, credentials, challenges, handles, binding
bytes, persistence, and consumption; it verifies nothing and authorizes neither
administrative action nor flood deletion. All authentication, batch-profile,
database, independent-review, and production gates remain OPEN.

The twenty-second Stage A slice adds a non-executing source policy for the
administrative step-up-v2 foundation. Exact target/imports, version and lifetime
constants, module members, immutable classes, false capabilities, validator
bodies, and closed calls are required. Added effectful or dynamic behavior
fails closed; the target is never imported or executed. This provides only
source-conformance evidence and no authentication, authorization, persistence,
concurrency, independent-review, or production authority.

The twenty-third Stage A slice locks the executable AST of the read-only
reporter view and restrictive response-header middleware without importing or
executing either target. Added endpoint/input/context/persistence/cookie/logging
behavior, unsafe methods, header relaxation, unknown targets, and malformed
source fail closed. This is source-conformance evidence only and provides no
browser, proxy, anonymity, submission, deployment, or production authority.

The twenty-fourth Stage A slice locks the executable AST of the controlled
security-interface errors and every mandatory unavailable adapter. Success
returns, plaintext/development fallbacks, new methods, dependency remapping,
input-bearing errors, logging/import side effects, unknown targets, and
malformed source fail closed without importing or executing either target.
This is negative-capability source evidence only and enables no real service or
production authority.

The twenty-fifth Stage A slice locks the complete executable AST of the inert
audit-v1 descriptor module. Changes to imports, constants, closed registries,
authorization windows, context-dependent denial, immutable fields, validators,
false authorization results, or added dynamic/effectful behavior fail closed.
The scanner never imports, executes, or echoes the target. This is source-
conformance evidence only and provides no CBOR/COSE, receipt verification,
audit append/durability, replay storage, protected-action, or production
authority.

The twenty-sixth Stage A slice locks the complete executable AST of the inert
alert-v1 descriptor module. Alert/severity/delivery registries, content-free
fields, validators, acknowledgement pairing, false durability/authorization
results, imports, and absence of dynamic/effectful behavior are fixed. The
scanner never imports, executes, or echoes the target. This provides no full
request profile, persistence, durable acceptance, delivery, acknowledgement,
Alert Service, or production authority.

The twenty-seventh Stage A slice locks the complete executable AST of the inert
report-bound step-up-v1 descriptor module. Protocol/lifetime, algorithms,
binding purpose, internal identifier/counter fields, timing, unused state,
validators, and every false verification/authorization result are fixed. The
scanner never imports, executes, or echoes the target. This provides no
challenge, credential, WebAuthn, artifact binding, session, persistence,
consumption, concurrency, external-service, or production authority.

The twenty-eighth Stage A slice locks the complete executable AST and sole-file
graph of the inert submission initial migration. Exact metadata-only fields,
states, state/version constraints, terminal timestamp pairing, imports, and
empty dependencies are fixed without importing or executing the source. This
provides no endpoint, credential, protected persistence, reconciliation,
PostgreSQL concurrency, external-service, or production authority.

The twenty-ninth Stage A slice locks the complete executable AST of the inert
submission error, state graph, pure transition planner, and metadata model. The
generic failure, one-way edges, single version increment, server time,
metadata-only constraints, and creation-only persistence boundary remain exact
without importing or executing target modules. This provides no endpoint,
credential, protected executor, reconciliation, concurrency, or production
authority.

The thirtieth Stage A slice locks the complete executable AST of the lifecycle
errors, closed state graphs, transition and lease planners, operation bindings,
metadata models, and persistence boundary. Server time, timeout and fencing
rules, constraints, creation-only saves, PostgreSQL checks, and the unavailable
executor remain exact without importing or executing targets. This provides no
protected transition, database write, concurrency proof, or production
authority.

The thirty-first Stage A slice locks the complete executable AST of `manage.py`,
the ASGI/WSGI entrypoints, and both installed metadata-app configurations. The
settings-module identity, Django factories, management boundary, app identities,
and absence of startup hooks remain exact without importing or executing the
targets. This provides no runtime, process, proxy, network, deployment, or
production authority.

The thirty-second Stage A slice locks the complete executable AST of the
application and migration package initializers. Passive package markers and the
reviewed `security_interfaces.__init__` re-export surface remain exact without
importing or executing the targets. This provides no runtime import isolation,
process, dependency, service, deployment, or production authority.

The thirty-third Stage A slice adds `python -m architecture_checks .` as an
aggregate fail-closed runner for the current static policy registry and wires
CI to call it. The command normalizes content-free violations from the existing
non-executing checks and provides no new runtime, browser, database,
external-service, deployment, or production authority.

The thirty-fourth Stage A slice adds a content-free repository-hygiene policy
to that aggregate runner. It inspects only tracked path names and `.gitignore`
rules, rejects committed local databases, logs, virtual environments,
secret/config material, export artifacts, temporary workspaces, quarantine
areas, user media, collected static output, and cache/test artifacts, and fails
closed without reading or echoing candidate file contents. It is repository
hygiene only and does not replace secret scanning, security review, deployment
validation, or production data-handling controls.

The thirty-fifth Stage A slice adds `scripts/verify` as the reviewed local
verification command and locks it with a non-executing source policy. The
script runs architecture policies, Django system checks, migration drift
checks, the Django test suite, Python compilation, and manifest validation,
then stops on the first failure. The policy fixes the exact command sequence
and executable AST without executing the script; passing provides only
developer-tooling conformance and no runtime, service, deployment,
independent-review, or production authority.

The thirty-sixth Stage A slice updates GitHub Actions CI to install the locked
dependency set with `--require-hashes` and delegate verification to
`scripts/verify`. A new non-executing workflow source policy locks read-only
repository permissions, pinned checkout/setup-python actions, Python 3.13,
hash-checked dependency installation, and the reviewed script entrypoint while
rejecting write/OIDC permissions, moving action refs, un-hashed installs,
`continue-on-error`, missing/out-of-root input, and source drift. It is CI
source conformance only and no supply-chain, deployment, independent-review, or
production gate is closed.

The thirty-seventh Stage A slice adds inert recovery credential descriptors for
the owner-approved version-1 Ticket ID and Recovery Secret shapes. Validation
accepts only exact canonical Base32/base64url text and returns content-free
shape evidence; it does not retain credential text or decoded bytes, generate
credentials, compute/compare HMAC verifier tags, persist plaintext secrets,
perform lookup, expose endpoints, call services, or authorize recovery.

A new non-executing recovery-descriptor source policy locks the exact imports,
constants, immutable classes, validators, metadata-only verifier purpose, and
false capability results. Generation, verifier, storage, lookup, logging,
network, file, Django integration, service-call, and authorization changes fail
closed. This closes no recovery, cryptographic-review, Response-DEK,
external-service, deployment, or production gate.

The thirty-eighth Stage A slice adds inert Response Note crypto descriptors for
the owner-approved version-1 profile. Validation accepts only exact static
algorithm/profile IDs, key/nonce/tag/frame/ciphertext sizes, scalar and UTF-8
limits, immutable context-size shape, AAD purpose, and the allowlisted
Response-DEK operation sequence. The descriptor does not canonicalize, frame,
CBOR-encode, encrypt, decrypt, hold real nonce/AAD/ciphertext/key-handle/DEK
values, persist protected bytes, call services, consume recovery authorization,
use receipts, inspect state, expose endpoints, or authorize response use.

A new non-executing response-crypto descriptor source policy locks the exact
imports, constants, enums, immutable classes, validators, and false capability
results. Canonicalization, CBOR, AEAD, random generation, Key Service,
storage, logging, network, file, Django integration, endpoint, service-call,
and authorization changes fail closed. This closes no Response Note crypto,
Response-DEK, Key Service, recovery authorization, independent-review,
deployment, or production gate.

The thirty-ninth Stage A slice adds inert Response Note text descriptors for
the owner-approved plain-text profile. Validation may transiently inspect
synthetic text for exact scalar, NUL, surrogate, line-ending, NFC, UTF-8 limit,
plain-text, no-HTML, and no-link-marker rules, but it returns only content-free
profile evidence and never returns or persists text, normalized text, canonical
bytes, digests, previews, drafts, frames, receipts, or state.

A new non-executing response-text descriptor source policy locks the exact
imports, constants, enums, immutable classes, validators, and false capability
results. Retained text, canonical bytes, digesting, drafting, persistence,
staging, endpoint, logging, network, file, Django integration, service-call,
finalization, and authorization changes fail closed. This closes no preview,
byte-freezing, artifact-binding, finalization, deployment, or production gate.

The fortieth Stage A slice adds inert Response Note schema descriptors for the
owner-approved AAD and ciphertext-envelope field order. Validation covers only
field names, primitive categories, fixed byte sizes, and public constant
values. It does not encode or parse CBOR, hold real identifiers, key handles,
nonce, AAD, ciphertext, plaintext, receipts, recovery authorization, or state,
persist bytes, call services, expose endpoints, or authorize response use.

A new non-executing response-schema descriptor source policy locks the exact
imports, constants, enums, field order, immutable classes, validators, and
false capability results. CBOR, retained context values, ciphertext handling,
cryptographic authentication, storage, logging, network, file, Django
integration, endpoint, service-call, and authorization changes fail closed.
This closes no deterministic-CBOR, envelope parsing, Key Service, deployment,
or production gate.

The forty-first Stage A slice adds inert no-JavaScript CAPTCHA descriptors for
the owner-approved version-1 protocol. Validation covers only static metadata
and strict text shapes: 16-byte identifiers encoded as 22-character unpadded
base64url text, six-character uppercase answers from the approved alphabet,
16-byte anonymous form scopes, five-minute non-sliding expiry, 15-minute cleanup
horizon, fixed PNG bounds, READY/CONSUMED/EXPIRED states,
SUBMIT_REPORT/RECOVER_RESPONSE purposes, anonymous global token-bucket limits,
and the open production gates.

A new non-executing CAPTCHA descriptor source policy locks the exact imports,
constants, enums, immutable classes, validators, and false capability results.
Generation, answer comparison, challenge persistence, media rendering,
IP/User-Agent/device binding, third-party CAPTCHA, endpoint enablement,
logging, network, file, Django integration, service-call, and authorization
changes fail closed. This closes no Pillow/font, audio/accessibility,
PostgreSQL concurrency, Challenge Service, gateway, deployment, or production
gate.

The forty-second Stage A slice adds inert request and multipart admission
descriptors for the owner-approved version-1 protocol. Validation covers only
static body, file, report-text, control-field, part-header, part-count,
boundary, streaming-buffer, deadline, method, content-type, and ordered
file-slot metadata.

A new non-executing request-admission descriptor source policy locks the exact
imports, constants, enums, immutable classes, validators, and false capability
results. HTTP parsing, multipart parsing, Django upload-handler installation,
file-byte access, filename exposure, sandbox-job creation, plaintext
persistence, submission acceptance, logging, network, file, Django integration,
and service-call changes fail closed. This closes no proxy, Django-handler,
CSRF, CAPTCHA, sandbox, audit, Key Service, no-spool, request-smuggling,
endpoint, deployment, or production gate.

The forty-third Stage A slice adds inert attachment-admission descriptors for
the owner-approved common version-1 file profile. Validation covers only static
count, size, kind, slot, extension, transient-filename, and trust-denial
metadata. It does not inspect file bytes, parse JPEG/PNG/PDF, create sandbox
jobs, persist originals, retain filenames, log request material, encrypt
attachments, expose safe views, or authorize uploads.

A new non-executing attachment-admission descriptor source policy locks the
exact imports, constants, enums, immutable classes, validators, and false
capability results. File-byte inspection, parser behavior, sandbox-job
creation, original-byte persistence, original-filename persistence,
request-material logging, upload authorization, file, network, Django
integration, and service-call changes fail closed. This closes no parser,
renderer, sandbox, encryption, safe-view, endpoint, deployment, or production
gate.

The forty-fourth Stage A slice adds inert safe-view descriptors for the
owner-approved operator attachment-view metadata. Validation covers only static
PNG output format, 8-bit sRGB profile, 144 DPI PDF-render metadata, output
resource limits, no-store/nosniff response headers, POST initiation, required
operator/state/lease/object bindings, non-durability, and ordinary original
download denial. It does not decrypt attachments, render files, validate PNG
bytes, call a sandbox, persist safe output, serve responses, inspect leases, or
authorize operator access.

A new non-executing safe-view descriptor source policy locks the exact imports,
constants, enums, immutable classes, validators, and false capability results.
Decryption, rendering, PNG validation, sandbox calls, output persistence,
response serving, operator-access authorization, file, network, Django
integration, and service-call changes fail closed. This closes no decrypt,
renderer, restricted-PNG verifier, sandbox, lease, response, endpoint,
deployment, or production gate.

The forty-fifth Stage A slice adds inert file-sandbox descriptors for the
owner-approved microVM boundary metadata. Validation covers only static
Firecracker reference, one-fresh-microVM profile, vCPU/RAM/process/file
descriptor/time limits, authenticated-vsock profile, read-only measured root,
guest RAM/tmpfs workspace, one-time job capability, no-production-credential
profile, and network/shell/swap/snapshot/storage denials. It does not boot
microVMs, execute parsers, open files, create jobs, exchange vsock messages,
inspect attachments, persist plaintext, or authorize file processing.

A new non-executing file-sandbox descriptor source policy locks the exact
imports, constants, enums, immutable classes, validators, and false capability
results. MicroVM boot, parser execution, file access, job creation, vsock
exchange, attachment inspection, plaintext persistence, file-processing
authorization, file, network, Django integration, and service-call changes fail
closed. This closes no Firecracker, jailer, kernel/rootfs, broker, vsock,
parser, renderer, sandbox-execution, deployment, or production gate.

The forty-sixth Stage A slice adds inert original-report crypto descriptors
for the owner-approved `docs/26` Report-DEK/object-subkey metadata.
Validation covers only static XChaCha20-Poly1305-IETF identifiers,
Report-DEK/subkey/nonce/tag sizes, fixed report-text and attachment frame
sizes, fixed ciphertext-and-tag sizes, object-kind/slot metadata, immutable
context-size shapes, AAD/KDF purposes, and allowlisted Report-DEK operation
names. It does not canonicalize report text, inspect attachments, frame
plaintext, generate keys/nonces, derive subkeys, encrypt, decrypt, encode or
parse CBOR, persist protected material, stream attachments, call a Key Service,
inspect state/audit receipts, expose endpoints, or authorize report use.

A new non-executing report-crypto descriptor source policy locks the exact
imports, constants, enums, immutable classes, validators, and false capability
results. Key generation, HKDF, AEAD, CBOR, nonce generation,
plaintext/ciphertext handling, Key Service calls, attachment streaming,
persistence, report-use authorization, file, network, Django integration, and
service-call changes fail closed. This closes no cryptographic-review, Key
Service, storage, sandbox, audit, export, deletion, restoration, deployment, or
production gate.

The forty-seventh Stage A slice adds inert original-report schema descriptors
for the owner-approved `docs/26` AAD/envelope field metadata. Validation covers
only ordered field names, primitive categories, fixed byte sizes, public
constant values, allowed public object kinds/slots, and allowed public
frame/ciphertext sizes. It does not encode or parse CBOR, hold report/attempt/
object IDs, hold key handles, hold nonces, hold ciphertext, call a Key Service,
stream attachments, inspect state/audit receipts, persist protected bytes,
expose endpoints, or authorize report use.

A new non-executing report-schema descriptor source policy locks the exact
imports, constants, enums, immutable classes, validators, and false capability
results. CBOR, context-value retention, ciphertext handling, service calls,
attachment streaming, persistence, report-use authorization, file, network,
Django integration, and service-call changes fail closed. This closes no
deterministic-CBOR, context-binding, ciphertext-handling, Key Service,
sandbox-streaming, persistence, deployment, independent-review, or production
gate.
