# 14 — Security Test Plan

This is a minimum plan, not a complete penetration-test program.

## Pre-code Stage A boundary

For the metadata-only Stage A described by
`docs/34_PRE_CODE_SECURITY_GATE.md`, test that:

- no model, migration, fixture, descriptor, log, or error field can contain
  report text, attachment bytes, original filenames, recovery credentials,
  verifier material, cryptographic keys, protected notes, or untrusted request
  metadata;
- every protected external-service adapter remains unavailable and fails
  closed without a fallback;
- the controlled dependency/error registry and unavailable-adapter executable
  AST remain exact; success returns, plaintext/development fallbacks, added
  methods, dependency remapping, input-bearing errors, logging, imports, and
  other side effects fail closed under a non-executing source policy;
- missing roots, unknown targets, malformed source, and policy mutations return
  controlled content-free violations without importing, executing, or echoing
  either security-interface source;
- no reporter submission, recovery, operator authentication/content, export,
  deletion, file handling, alert, or finalization endpoint exists;
- lifecycle transitions reject stale state, stale lease generation, duplicate
  operation IDs, cross-report binding, and conflicting concurrent intent;
- immutable operation descriptors reject the wrong actor, report, state
  version, lease ID, lease owner, lease generation, lease state, idle deadline,
  and absolute deadline;
- SQLite and a merely capability-shaped backend cannot enable a persistence
  write before the reviewed PostgreSQL executor and multi-process proof exist;
- audit-v1 structural descriptors accept only the closed event/actor registry,
  exact immutable identifier/nonce lengths, CBOR-uint range, and exact
  unambiguous non-sliding authorization lifetime;
- structural audit validation never becomes receipt/signature verification or
  protected-action authorization, and context-dependent/incomplete profiles
  remain fail closed;
- the complete executable AST of the inert audit-v1 descriptor module remains
  exact; registry, field, validator, lifetime, success-return, import, dynamic,
  and side-effect changes fail closed without importing or executing it;
- submission-audit descriptors accept only the exact approved
  `SUBMISSION_ACCEPTANCE_REQUESTED`, `SUBMISSION_RECEIVED`, and
  `SUBMISSION_ACCEPTANCE_FAILED` order, timing labels, authorization windows,
  durable-receipt flags, and allowed/forbidden payload metadata;
- submission-audit validation and source policy reject event append, receipt
  creation/verification, attempt-state inspection, Audit Service calls, key
  creation, submission metadata persistence, endpoint behavior, and submission
  authorization without importing or executing the target;
- submission acceptance checkpoint descriptors accept only the exact approved
  Phase 0-6 phase order, checkpoint names, requirement labels, and forbidden
  runtime capability categories;
- submission acceptance checkpoint validation and source policy reject request
  parsing, credential validation, attempt claiming, audit append, receipt
  verification, Key Service calls, encryption, storage writes, database
  commits, response rendering, reconciliation, endpoint behavior, and
  submission authorization without importing or executing the target;
- submission-attempt credential descriptors accept only the approved single-use
  semantics, two-hour non-sliding pre-claim lifetime, POST body/protected
  same-site cookie transport labels, URL/query/referrer/header-log denials,
  forbidden report/recovery/network/account/device bindings, minimum
  verifier/index representation, database uniqueness/state-version metadata,
  and no-log/no-audit persistence denials;
- attempt-credential validation and source policy reject credential generation
  or verification, plaintext credential persistence, cookie installation,
  request inspection, attempt claiming, logging, audit writes, reporter account
  creation, endpoint behavior, submission authorization, and report-read
  authorization without importing or executing the target;
- submission-reconciliation descriptors accept only the exact approved maximum
  scan interval, progress deadline, cleanup retry cap, persistent-cleanup-alert
  threshold, candidate states, terminal outcomes, action names, alert type, and
  allowed/forbidden content-free payload metadata;
- submission-reconciliation validation and source policy reject report-content
  scanning, plaintext decryption, credential creation, audit append, receipt
  verification, service calls, ciphertext deletion, state mutation, scheduling,
  endpoint behavior, and submission authorization without importing or
  executing the target;
- submission retry descriptors accept only the exact approved duplicate/retry
  source set, required one-database-winner/no-second-pipeline outcomes,
  no-redisplay and controlled-indeterminate-response results, and forbidden
  signal categories;
- submission retry validation and source policy reject request parsing,
  credential verification, attempt claiming, database-state inspection,
  report/Report-DEK creation, audit append, credential redisplay, status
  oracles, service calls, endpoint behavior, and submission authorization
  without importing or executing the target;
- submission failure descriptors accept only the exact approved failure-boundary
  labels, required-result labels, content-free flags, and fail-closed flags;
- submission failure validation and source policy reject request handling,
  submission pipeline start, service calls, storage writes, key creation,
  plaintext persistence, audit append, state mutation, credential return,
  endpoint behavior, and submission authorization without importing or
  executing the target;
- submission idempotency descriptors accept only the exact approved
  sequential-retry, synchronized-parallel-copy, multi-process, reconciliation,
  stale-version, response-loss, crash-injection, cleanup, and logging
  scenarios plus required invariants and forbidden runtime capability
  categories;
- submission idempotency validation and source policy reject parallel request
  execution, request handling, attempt-state inspection, database locking,
  storage writes, Report-DEK creation, audit append, artifact reconciliation,
  reporter-input logging, endpoint behavior, and submission authorization
  without importing or executing the target;
- submission credential-response descriptors accept only the one live
  post-acceptance display opportunity, controlled indeterminate retry result,
  permitted Ticket ID/Recovery Secret response-field names, and forbidden
  persistence categories for plaintext secrets, redisplay/replacement state,
  `credentials_delivered` claims, content hashing, request headers, and raw
  errors;
- credential-response validation and source policy reject credential
  generation, secret persistence, Recovery Secret redisplay, replacement
  issuance, delivery claims, content deduplication, response rendering,
  endpoint behavior, recovery authorization, and submission authorization
  without importing or executing the target;
- alert-v1 descriptors enforce the exact ten alert/severity pairs, delivery
  states, actor pairing, identifier lengths, timestamp range, and
  acknowledgement pairing while rejecting unknown/arbitrary values;
- a structural alert acceptance response never proves durable inbox/outbox
  commit, SMTP delivery, human acknowledgement, or protected authorization;
- the complete executable AST of the inert alert-v1 descriptor module remains
  exact; registry, field, validator, false durability/authorization result,
  import, dynamic, and side-effect changes fail closed without execution;
- report-bound step-up-v1 components accept only exact identifier/counter
  shapes, approved COSE algorithm codes, binding-purpose metadata, and the
  non-sliding 120-second lifetime;
- Stage A step-up types cannot hold challenges, opaque browser handles,
  credentials, artifact bytes, HMAC bindings, consumed authorizations, or
  incomplete operation/state/artifact registry values, and authorize nothing;
- the complete executable AST of the report-bound step-up-v1 descriptor module
  remains exact; field, registry, timing, validator, false verification or
  authorization result, import, dynamic, and effect changes fail closed;
- recovery credential descriptors accept only the exact 16-byte/26-character
  uppercase unpadded Base32 Ticket ID shape and 32-byte/43-character unpadded
  base64url Recovery Secret shape;
- recovery credential validation rejects lowercase Ticket IDs, padding,
  whitespace, alternate alphabets, Unicode, non-string inputs, wrong lengths,
  and non-canonical encodings without returning or persisting credential text
  or decoded bytes;
- the recovery descriptor verifier profile is metadata-only and cannot
  generate credentials, compute a verifier, store a plaintext secret, perform
  lookup, expose an endpoint, or authorize recovery;
- the complete executable AST of the recovery descriptor module remains exact;
  import, constant, field, validator, false-capability, generation, verifier,
  storage, logging, endpoint, service-call, and authorization changes fail
  closed without importing or executing it;
- recovery failure descriptors accept only the exact approved random-source,
  collision, encoding, verifier/key, unknown version/key, HMAC mismatch,
  unavailable/expired/destroyed response, concurrent first-read, Response-DEK
  expiry, and credential logging/telemetry failure labels with generic
  fail-closed result metadata;
- recovery failure validation and source policy reject random generation,
  credential decoding, verifier calls, HMAC comparison, response-state reads,
  Key Service calls, first-read mutation, credential logging, endpoint
  behavior, and recovery authorization without importing or executing the
  target;
- recovery key lifecycle descriptors accept only the exact approved 32-byte
  verifier-key size, active/retired/destroyed states, separated key purposes,
  forbidden source/settings/database/log/audit/browser/response locations, and
  lifecycle requirements for service-selected key IDs, no silent fallback,
  restore proof, fail-closed loss, and no Response-DEK authority;
- recovery key lifecycle validation and source policy reject key generation,
  key storage, request-time key selection, rotation execution, destruction,
  verifier-record rewriting, Key Service calls, Response-DEK authorization,
  endpoint behavior, and recovery authorization without importing or executing
  the target;
- recovery verification descriptors accept only the exact approved full-length
  HMAC-SHA-256, constant-time full-tag comparison, boolean-only result,
  necessary-not-sufficient HMAC success, canonical input, dummy-verification,
  generic-response, timing-distribution-test, and no-perfect-
  indistinguishability metadata;
- recovery verification validation and source policy reject HMAC computation,
  tag comparison, dummy-verification execution, expected-tag or partial-match
  disclosure, response-state reads, CAPTCHA validation, Key Service calls,
  Response-DEK authorization, credential logging, endpoint behavior, and
  recovery authorization without importing or executing the target;
- recovery verifier-record descriptors accept only the exact approved
  `scheme_version`, `verifier_key_id`, and `verifier_tag` field metadata,
  full 32-byte tag size, server-controlled key ID, no plaintext secret, no raw
  verification key, database-alone secret-test denial, removal with recovery
  state, terminal invalidation, and forbidden-material categories;
- recovery verifier-record validation and source policy reject Recovery Secret,
  raw key, raw HMAC message, report content, DEKs, operator identity,
  persistence, verifier computation, candidate-secret testing, lookup,
  database writes, endpoint behavior, and recovery authorization without
  importing or executing the target;
- recovery HMAC-message descriptors accept only the exact approved ASCII domain
  label, terminating zero separator, 16-byte Ticket ID field, 32-byte Recovery
  Secret field, fixed order, fixed lengths, and purpose-specific framing
  metadata;
- recovery HMAC-message validation and source policy reject credential-value
  acceptance, byte concatenation, HMAC computation, canonical-message
  retention, Recovery Secret storage, verifier-key access, tag return, message
  logging, endpoint behavior, and recovery authorization without importing or
  executing the target;
- Recovery Verifier Service descriptors accept only the exact approved
  create-only and boolean-verify operation labels, authenticated/encrypted/
  bounded channel requirements, body/credential log exclusions, create-output
  and verify-output rules, and forbidden-capability metadata;
- Recovery Verifier Service validation and source policy reject service call
  implementation, credential generation, HMAC computation, tag comparison,
  verifier-record persistence, lookup, reporter-supplied key IDs, raw-key/tag/
  partial-match disclosure, response-state reads, Key Service calls,
  Response-DEK authorization, credential logging, endpoint behavior, and
  recovery authorization without importing or executing the target;
- Response Note crypto descriptors accept only the exact version-1 algorithm,
  content-profile, key, nonce, tag, plaintext-frame, ciphertext/tag, immutable
  context-size, AAD-purpose, and Response-DEK operation profile shapes;
- response crypto validation cannot hold Response Note text, ciphertext, nonce
  bytes, AAD bytes, real key handles, Response-DEK material, recovery
  authorization, audit receipts, or state rows, and all capability flags remain
  false;
- the complete executable AST of the response crypto descriptor module remains
  exact; import, constant, registry, field, validator, false-capability,
  canonicalization, CBOR, AEAD, Key Service, storage, logging, endpoint, and
  authorization changes fail closed without importing or executing it;
- Response Note text descriptors accept only the exact plain-text profile:
  Unicode scalar values, NUL rejection, LF line-ending profile, NFC
  normalization rule, strict UTF-8, 5,000-scalar and 20,000-byte limits,
  conservative no-HTML markers, and conservative no-link markers;
- response text validation returns no submitted text, normalized text,
  canonical bytes, digest, preview, draft, frame, receipt, state, persistence,
  endpoint, finalization, or authorization capability;
- the complete executable AST of the response text descriptor module remains
  exact; import, constant, registry, field, validator, false-capability,
  retained-text, canonical-byte, digest, draft, persistence, staging, endpoint,
  logging, service-call, finalization, and authorization changes fail closed
  without importing or executing it;
- Response Note schema descriptors accept only the exact ordered AAD and
  ciphertext-envelope field names, primitive categories, public constant
  values, and fixed byte-size metadata from the approved version-1 profile;
- response schema validation returns no actual report ID, response ID,
  finalization ID, key handle, nonce, AAD bytes, ciphertext, plaintext, receipt,
  recovery authorization, state, persistence, endpoint, Key Service, or
  authorization capability;
- the complete executable AST of the response schema descriptor module remains
  exact; import, constant, registry, field-order, validator, false-capability,
  retained-context, ciphertext, CBOR, cryptographic, persistence, endpoint,
  logging, service-call, and authorization changes fail closed without
  importing or executing it;
- administrative step-up-v2 foundations accept only exact 16-byte authorization,
  administrator, session, and device identifiers, binding-purpose/key-epoch
  metadata, a non-sliding 120-second lifetime, and an unused-only state;
- v2 foundations reject unknown purposes, malformed identifiers/counters/times,
  consumed state, and sensitive values; they contain no operation/target/
  artifact profile, credential, challenge, handle, binding bytes, persistence,
  consumption, WebAuthn verification, or flood/administrative authorization;
- the current Reporter Gateway and root URL configuration pass exact
  deny-by-default import allowlists; sensitive/model/service/network imports,
  star/parent-relative imports, dynamic imports, `eval`, and `exec` fail;
- static architecture scanning parses but never imports or executes the target
  source, fails closed for syntax/path/read errors, and is never represented as
  runtime credential/process/network isolation;
- the exact executable AST of `manage.py`, ASGI/WSGI entrypoints, and installed
  metadata-app configurations remains fixed; alternate settings, logging,
  network/file effects, application wrappers, early command execution,
  `AppConfig.ready()` hooks, malformed source, unknown targets, and missing
  roots fail closed without import, execution, or echo;
- application and migration package initializers remain fixed to their reviewed
  executable AST; passive package markers and the `security_interfaces` re-
  export surface cannot gain imports, exports, startup side effects, migration
  initializer code, dynamic behavior, malformed source, unknown targets, or
  missing roots without a controlled fail-closed violation;
- the aggregate `python -m architecture_checks .` runner executes the complete
  current static policy registry, returns success only when every policy passes,
  and formats failures without echoing target source or sensitive values;
- the local `scripts/verify` command remains locked to the reviewed sequence:
  architecture policies, Django system check, migration drift check, Django
  tests, Python compilation, and manifest validation;
- the verification-script source policy parses but never executes
  `scripts/verify`, rejects removed steps and executable-source drift, fails
  closed for missing/malformed/out-of-root input, and never echoes script source
  or injected sentinel values;
- the GitHub Actions CI workflow remains locked to read-only repository
  permissions, pinned checkout/setup-python actions, Python 3.13, locked
  dependency installation with `--require-hashes`, and `scripts/verify`;
- the CI-workflow source policy rejects write/id-token permissions, moving
  action refs, un-hashed dependency installation, `continue-on-error`, missing
  workflow input, out-of-root input, and reviewed workflow hash drift without
  executing the workflow or echoing injected values;
- the test-only PostgreSQL concurrency scaffold contains exactly the active
  report/lease/operation exclusions and stale report-version/lease-generation
  scenarios currently modeled, using only internally generated UUID metadata;
- every scaffold case requires 20–100 unique contenders, a synchronized start,
  at least two requested processes, and a dedicated connection count equal to
  the contender count;
- the scaffold runner remains unavailable on SQLite, configuration/backend
  failure, and a merely capability-shaped PostgreSQL backend, with zero model
  writes and no skipped/placeholder run represented as concurrency evidence;
- the lifecycle migration package contains exactly one initial migration with
  no dependency, data/SQL/custom-code operation, additional numbered migration,
  dynamic expression, unlisted import/call, or field/model/type drift;
- the migration's exact metadata-only model fields and constructor types match
  the reviewed profile, and Django `makemigrations --check --dry-run` reports no
  pending model change;
- the submission migration package likewise contains exactly its reviewed
  initial migration and complete executable AST; field, state, constraint,
  timestamp, import, dynamic, data/SQL/custom-code, dependency, additional-file,
  malformed-source, and out-of-root changes fail closed without execution or
  echoed source;
- the submission error, states, transition planner, and metadata model retain
  their exact executable AST; new states/edges, backward acceptance, sensitive
  fields, caller-selected time, logging, weakened constraints, successful
  existing-row mutation, database capability, malformed source, unknown target,
  and missing-root changes fail closed without import, execution, or echo;
- the lifecycle errors, state registries, transition/lease planners, operation
  bindings, metadata models, and persistence boundary retain their exact
  executable AST; new/backward states, relaxed timing, skipped fencing,
  sensitive fields, weakened constraints, backend relaxation, logging, writes,
  success returns, malformed source, unknown targets, and missing roots fail
  closed without import, execution, or echo;
- the inert finalization sequence contains only the received-request checkpoint
  followed by the exact twelve approved actions, rejects every skip, reverse,
  repeat, unknown value, wrong operation, non-OPEN state, internally
  inconsistent version, forged idempotency ID, or malformed lease binding, and
  never echoes rejected values;
- an inert finalization edge is immutable, content-free, non-authorizing and
  non-persisting; its executor always returns the same controlled unavailable
  failure and leaves all lifecycle tables empty;
- the inert operator-deletion sequence contains only the received-request
  checkpoint followed by the exact ten approved actions in `docs/32`, accepts
  only an existing `DELETE_REPORT`/OPEN/current-lease binding, and rejects every
  skip, reverse, repeat, unknown value, flood/finalization operation,
  internally inconsistent version, malformed lease, or forged idempotency ID;
- an inert operator-deletion edge is immutable, content-free, non-authorizing,
  non-persisting, and explicitly non-destructive; its executor always returns
  the same controlled unavailable failure and leaves all lifecycle tables empty;
- non-executing orchestration scanning accepts only the exact current
  `finalization.py`, `deletion.py`, `retention.py`, `cleanup.py`,
  `metadata_retention.py`, and `audit_retention.py` import/member/call profiles,
  closed enums, content-free immutable snapshot/plan fields, false capability
  flags, and executors whose only result is the controlled unavailable exception;
- nested/star imports, database/network/crypto/I/O or self-selected-time calls,
  dynamic/effectful syntax, attribute/subscript mutation, content/authorizing
  fields, altered executor bodies, missing targets, malformed source, and
  out-of-root paths fail closed without importing, executing, or echoing source;
- retention database/key/I/O/logging calls, imported type/constant/member
  shadowing, recovery/verifier/content fields, changed capability flags, and
  altered executor behavior fail the same non-executing source policy;
- cleanup storage/scheduler/audit/alert/I/O/logging calls, imported constants or
  member shadowing, object/path/provider/content fields, changed timing members
  or capability flags, and altered executor behavior fail the same policy;
- terminal-metadata database/scheduler/audit/Key-Service/I/O/logging calls,
  imported constant/member shadowing, public-ticket/recovery/path/content fields,
  changed capability flags, and altered executor behavior fail the same policy;
- audit-retention database/scheduler/witness/I/O/logging calls, imported timing
  or member shadowing, receipt/content/key fields, changed evidence/disposition
  registries or capability flags, and altered executor behavior fail the policy;
- response-retention planning fixes unread expiry at exactly 90 times 24 hours
  after response availability, recognizes a stored first read strictly before
  that boundary only with one full non-sliding 72-hour window, never proposes a
  first read, and makes expiry win at either exact boundary;
- malformed identifiers/state/version/timestamps, caller-shaped or naive time,
  a future availability/first-read time, inconsistent stored deadlines, a first
  read at or after unread expiry, and every attempt to execute the plan fail
  closed without persistence, decryption, destruction, or echoed input;
- inert ciphertext-cleanup timing fixes the first three base delays, the exact
  one-hour/24-hour tier boundaries, indefinite six-hour tier, 10% jitter ceiling,
  one-minute reconciler ceiling, and the alert transition at exactly 15 minutes;
- malformed cleanup UUIDs/counters/timestamps, reversed or future failures,
  premature/future alert records, untrusted time, and every execution attempt
  fail closed without selecting jitter, scheduling, persistence, service calls,
  alert submission, deletion, database writes, or echoed input;
- terminal metadata remains retained without a removal time until cleanup is
  durably confirmed; once confirmed, the earliest review boundary is exactly
  30 times 24 elapsed hours in UTC and equality does not authorize removal;
- malformed retention/cleanup UUIDs, naive, caller-shaped, or future timestamps,
  and every execution attempt fail closed without Ticket ID lookup deletion,
  metadata mutation, persistence, job scheduling, service calls, database
  writes, or echoed input;
- audit-retention planning fixes event/receipt/proof review at exactly 365 times
  24 elapsed hours and checkpoint/consistency/key-manifest/witness review at
  exactly 730 times 24 elapsed hours from trusted collector time;
- an evidence dependency required for retained verification blocks expiry review
  after the minimum period; malformed UUID/class/dependency/timestamps and every
  execution attempt fail closed without audit deletion, batch persistence,
  witness exposure, service calls, database writes, or echoed input;
- SQLite results are never represented as PostgreSQL concurrency evidence;
- the application still cannot accept a real report.

## Reporter input / logging

Test that:

- report text never appears in logs;
- original filename never appears in logs;
- Recovery Secret never appears in logs;
- POST bodies are not logged;
- parser exceptions cannot inject user input into logs;
- newline/control characters cannot forge log entries.

## Submission sequencing

Under the approved sequence, test every failure boundary between audit acceptance, key creation, encryption, metadata/ciphertext persistence, and one-time credential delivery.

Verify:

- audit unavailability follows the approved fail-closed behavior;
- no accepted report lacks the required truthful audit evidence;
- retry after connection loss cannot silently duplicate a report;
- plaintext never reaches durable temporary/storage paths;
- the system never claims one-time credentials were delivered when the response was lost;
- orphan keys/ciphertexts/metadata are reconciled without logging reporter data.

For `20_SUBMISSION_ACCEPTANCE_PROTOCOL.md`, also verify:

- expired, unknown, consumed, and replayed attempt credentials fail closed;
- synchronized parallel POST copies create one attempt owner and at most one
  Report-DEK, metadata record, ciphertext set, and `SEALED` report;
- `SUBMISSION_ACCEPTANCE_REQUESTED` is durable before key/material creation;
- `SUBMISSION_RECEIVED` is emitted only after exact staged objects and metadata
  are durably verified;
- Stage A submission-audit descriptor/source-conformance tests prove only the
  approved phase order, timing labels, receipt-required flags, and
  content-free payload allow/deny metadata, and reject any append, receipt,
  service, persistence, key, endpoint, or authorization capability;
- Stage A submission acceptance checkpoint descriptor/source-conformance tests
  prove only the approved Phase 0-6 order, checkpoint names, requirement
  labels, and forbidden runtime capability metadata, and reject request
  parsing, credential validation, attempt claiming, audit append, receipt
  verification, Key Service, encryption, storage, database, response,
  reconciliation, endpoint, or authorization capability;
- Stage A attempt-credential descriptor/source-conformance tests prove only the
  approved single-use, two-hour pre-claim, allowed/forbidden transport,
  forbidden binding, minimum durable-representation, and no-log/no-audit
  metadata, and reject credential generation/verification, cookie installation,
  request inspection, attempt claiming, endpoint, logging, audit write,
  submission authorization, or report-read capability;
- Stage A submission-reconciliation descriptor/source-conformance tests prove
  only the approved scan/progress/cleanup/alert timing metadata, candidate
  states, terminal outcomes, action registry, and payload allow/deny metadata,
  and reject content scanning, credentials, receipt verification, service
  calls, deletion, state mutation, scheduling, endpoint, or authorization
  capability;
- Stage A submission retry descriptor/source-conformance tests prove only the
  approved duplicate/retry source labels, one-winner/no-second-pipeline
  outcomes, no-redisplay, controlled indeterminate response, and forbidden
  signal metadata, and reject request parsing, credential verification,
  attempt claiming, database-state inspection, report/DEK creation, audit
  append, status-oracle, service, endpoint, or authorization capability;
- Stage A submission failure descriptor/source-conformance tests prove only
  the approved failure-boundary, required-result, content-free, and fail-closed
  metadata, and reject request handling, pipeline start, service, storage, key,
  plaintext persistence, audit, state mutation, credential return, endpoint, or
  authorization capability;
- Stage A submission idempotency descriptor/source-conformance tests prove only
  the approved concurrency/idempotency scenario and invariant metadata, and
  reject parallel request execution, request handling, attempt inspection,
  database locking, storage writes, Report-DEK creation, audit append,
  artifact reconciliation, reporter-input logging, endpoint, or authorization
  capability;
- Stage A credential-response descriptor/source-conformance tests prove only
  the approved one-time display and lost-response metadata, and reject secret
  persistence, redisplay, replacement credentials, `credentials_delivered`
  claims, content deduplication, endpoint, response rendering, recovery
  authorization, or submission authorization capability;
- Stage A recovery key-lifecycle descriptor/source-conformance tests prove only
  the approved verifier-key size, state, separation, forbidden-location, and
  lifecycle requirement metadata, and reject key generation, key storage,
  key selection, rotation, destruction, verifier rewriting, Key Service calls,
  Response-DEK authorization, endpoint, or recovery authorization capability;
- Stage A recovery verification descriptor/source-conformance tests prove only
  the approved full-length HMAC, comparison, result-rule, input, uniformity,
  and forbidden-capability metadata, and reject HMAC computation, tag
  comparison, dummy execution, tag disclosure, partial-match detail,
  response-state access, CAPTCHA validation, Key Service calls, Response-DEK
  authorization, credential logging, endpoint, or recovery authorization
  capability;
- Stage A recovery verifier-record descriptor/source-conformance tests prove
  only the approved persisted-record field, full-tag, requirement, and
  forbidden-material metadata, and reject secret/key/raw-message/DEK fields,
  persistence, verifier computation, candidate-secret testing, lookup,
  database writes, endpoint, or recovery authorization capability;
- Stage A recovery HMAC-message descriptor/source-conformance tests prove only
  the approved canonical layout metadata, and reject credential parsing, byte
  concatenation, HMAC computation, message retention, key access, tag output,
  logging, endpoint, or recovery authorization capability;
- Stage A Recovery Verifier Service descriptor/source-conformance tests prove
  only the approved operation, channel, create-rule, verify-rule, and
  forbidden-capability metadata, and reject service calls, HMAC/tag work,
  persistence, lookup, response-state reads, Key Service calls, Response-DEK
  authorization, credential logging, endpoint, or recovery authorization
  capability;
- lost responses never cause credential re-display, replacement credentials,
  or a duplicate report for the same attempt;
- no event or state claims that the reporter received or saved credentials;
- the reconciler cannot obtain plaintext or construct credentials and can only
  finish the evidenced transition or destroy scoped staged material;
- crash injection at each approved phase reaches only an allowed state.

## Original report cryptography

Test:

- RFC 5869 HKDF-SHA-256 vectors and per-report/object/purpose subkey separation;
- pinned XChaCha20-Poly1305 vectors, random nonce uniqueness, combined-mode
  lengths, and byte-identical idempotent retries;
- deterministic-CBOR KDF/AAD/envelope encoding and rejection of every context,
  object, slot, attempt, or key-handle substitution;
- canonical UTF-8/NFC text and fixed 20,005-byte frame validation;
- OPEN and Emergency Export recover the exact same accepted canonical text
  bytes, while no raw pre-normalization representation is persisted, encrypted,
  queued, logged, audited, or backed up;
- Stage A text descriptor/source-conformance tests prove only the transient
  UTF-8/NFC/LF, scalar/byte-limit, NUL/surrogate rejection, and canonical
  original metadata shape, and reject raw-text retention, canonical-byte
  output, frame construction, encryption, persistence, logging, endpoint, and
  submission-authorization additions;
- Stage A frame descriptor/source-conformance tests prove only ordered
  report-text and attachment plaintext-frame layout metadata, public
  PDF/JPEG/PNG kind codes, big-endian length-field markers, fixed sizes, and
  zero-padding requirements, and reject plaintext handling, frame
  construction/parsing, padding-byte validation, attachment inspection,
  encryption, persistence, endpoint, and authorization additions;
- attachment framing at 0 and 5,242,880-byte boundaries, fixed ciphertext size,
  kind binding, zero padding, and oversized rejection;
- Reporter Gateway cannot decrypt existing content, Operator Console cannot
  receive original attachment bytes, and sandbox streams cannot be redirected;
- provisional/staged/SEALED activation crashes and races never expose content or
  issue credentials before every approved condition;
- Report-DEK destruction makes every object permanently unusable across live
  replicas, rollback, snapshot, restore, and disaster recovery.
- Stage A descriptor/source-conformance tests prove only the reviewed inert
  Report-DEK, subkey, frame, envelope, object-kind, slot, and operation
  metadata shape, and reject generation, HKDF, AEAD, CBOR, plaintext,
  ciphertext, Key Service, stream, persistence, endpoint, and authorization
  additions.
- Stage A schema descriptor/source-conformance tests prove only ordered
  original-report AAD/envelope field metadata and reject CBOR,
  context-value retention, ciphertext handling, service calls, attachment
  streaming, persistence, endpoints, and authorization.

## Recovery enumeration

Test:

- random invalid Ticket ID;
- valid Ticket ID + invalid secret;
- nonexistent Ticket ID + random secret;
- answered ticket;
- unanswered ticket;
- expired response.

Non-success responses should be intentionally uniform in status/body/timing envelope where feasible.

## Session controls

Test:

- CLAIM expires after 5 minutes;
- one operator cannot claim two active reports;
- two operators cannot open the same report concurrently;
- refresh during valid lease remains same OPEN;
- idle timeout after 5 minutes;
- absolute timeout at 60 minutes even with activity;
- stale browser cannot resume after lease invalidation;
- reopening requires reason.
- stale lease generation cannot perform any sensitive action;
- a new generation fences old tabs, delayed requests, and late retries;
- server-side time, not client time, controls idle/absolute expiry;
- database constraints prevent one operator/report from acquiring conflicting active leases.

## Finalization

Test:

- finalization without step-up MFA fails;
- finalization without CAPTCHA fails;
- finalization with audit unavailable fails closed;
- failure to persist Response Note leaves report intact;
- successful finalization destroys report key;
- stale sessions cannot read report after finalization;
- double-submit cannot cause inconsistent state.
- Response Note remains externally unavailable throughout `FINALIZING` until Report-DEK destruction is confirmed and durably audited;
- step-up authorization is bound to operator, ticket, `FINALIZE_RESPONSE`, and exact Response Note digest;
- a step-up authorization cannot be replayed or used for another operation/ticket/artifact;
- crash after each critical finalization phase resumes idempotently with the outcomes defined in `03_DATA_LIFECYCLE.md`;
- export/finalization races have one fenced, deterministic winner;
- Report-DEK destruction confirmation cannot be converted back into a readable-report state.
- committed entry to `FINALIZING` always has the exact staged Response Note ciphertext available for resume;
- after entry to `FINALIZING`, operator rendering/editing, reopen, and Emergency Export fail closed;
- crash after consumed step-up/audit receipt but before committed `FINALIZING` leaves the report OPEN and requires a new authorization.

## Key destruction

Test disaster-recovery scenarios:

- restore DB snapshot after report destruction;
- restore blob snapshot after report destruction;
- restore key-service snapshot/backup if supported.
- restore/rollback each supported live-replica state, including delayed or stale replica scenarios;
- restore combinations of wrapped/encrypted per-object key records, retained infrastructure keys, DB/blob backups, and snapshots;
- repeat the restore tests for expired/destroyed Response-DEKs.

Destroyed report MUST remain undecryptable.

This test is a release gate for the key-management design.

For `32_RETENTION_AND_DELETION_PROTOCOL.md`, also verify:

- 90-day unread expiry versus first read has one server-authoritative winner,
  and a winning pre-deadline read receives exactly the existing 72-hour window;
- operator deletion is OPEN-only and binds the exact reason, protected note,
  operator/session/lease/generation/state, CAPTCHA, step-up, and audit receipt;
- committed deletion states never reopen after crash or uncertain key outcome;
- flood deletion cannot start before closed admission, capacity attestation,
  administrator declaration, two distinct Operator approvals, and audit gates;
- flood selection is SEALED-only, content-blind, newest-first, capped, and skips
  a candidate that loses the state race without substituting another;
- each report destruction has its own pre-action receipt and partial batches
  record truthful per-item outcomes;
- cleanup retry/alert and 30-day metadata expiry cannot recreate keys or shorten
  audit retention.

For each candidate Key Service, execute the complete production-equivalent
`docs/27` PoC, including:

- every caller/operation negative-capability combination;
- synchronized create/activate/use/expiry/destroy races across nodes;
- a replica isolated before destruction and rejoined afterward;
- pre-destruction Raft/product exports plus filesystem, block, VM, memory,
  HSM/KMS/seal, configuration, and combined-backup restoration;
- clock rollback, old receipt/capability replay, leader/quorum failure, upgrade,
  node replacement, seal/key rotation, and complete disaster recovery;
- a binary failure if any restored environment can decrypt one canary.

## File upload

Test:

- exact encoded-body, aggregate-file, part/header/control, timeout, idle, and
  bounded-memory limits from `docs/30` at every ingress/application boundary;
- CL/TE, duplicate/conflicting headers, HTTP/1↔HTTP/2 translation, chunked,
  compressed, nested, truncated, slow, and multipart differential corpora;
- reverse proxy, WAF/APM, Django, queue, filesystem, swap, and backup inspection
  proves no request body/file spool or capture and no automatic POST replay;

- extension spoofing;
- MIME spoofing;
- polyglots;
- oversized body;
- path traversal filename;
- Unicode filename tricks;
- invalid filename characters;
- PDF JavaScript;
- embedded files;
- launch actions;
- malformed PDF;
- decompression/resource exhaustion;
- corrupted JPEG/PNG;
- image parser bombs;
- content with mismatched signature.
- structural-profile boundary cases once the profile is approved;
- page/object/decompression/dimension/resource limits once approved;
- verify proxy, Django upload handling, workers, and temporary workspaces do not durably spool plaintext.

Current Stage A evidence additionally tests that the inert request-admission
descriptor accepts only the approved 21 MiB body, 5 MiB per-file, 20 MiB
aggregate-file, text/control/header/part/boundary, streaming-buffer, deadline,
method/content-type, and file-slot metadata. Its exact-source policy rejects
HTTP/multipart parsing, Django upload-handler installation, file-byte access,
filename exposure, sandbox job creation, plaintext persistence, submission
acceptance, dynamic behavior, and source echoing. These tests do not enable an
upload endpoint or custom handler.

Current Stage A evidence also tests that the inert attachment-admission
descriptor accepts only the approved common file count, size, kind, slot,
extension, transient-filename, and trust-denial metadata. Its exact-source
policy rejects file-byte inspection, format parsing, sandbox-job creation,
original-byte persistence, filename persistence, request-material logging,
upload authorization, dynamic behavior, and source echoing. These tests do not
enable parser, sandbox, upload, safe-view, or encryption behavior.

Current Stage A evidence also tests that the inert safe-view descriptor accepts
only the approved PNG output, 8-bit sRGB, 144 DPI, output/resource limit,
no-store/nosniff response, binding, non-durability, and ordinary-download-denial
metadata. Its exact-source policy rejects decryption, rendering, sandbox calls,
PNG-byte validation, output persistence, response serving, operator-access
authorization, dynamic behavior, and source echoing. These tests do not enable
safe-view generation or delivery.

Current Stage A evidence also tests that the inert file-sandbox descriptor
accepts only the approved Firecracker reference, compute limits, isolation
denials, authenticated-vsock metadata, read-only/RAM/tmpfs workspace profile,
one-time capability, and no-production-credential metadata. Its exact-source
policy rejects microVM boot, parser execution, file access, job creation, vsock
exchange, attachment inspection, plaintext persistence, authorization, dynamic
behavior, and source echoing. These tests do not execute or prove a sandbox.

Unsafe/uncertain should fail closed.

## File sandbox

Test:

- no network egress;
- no access to application secrets;
- process timeout;
- memory limit;
- temporary-file cleanup;
- crash cleanup;
- sandbox escape assumptions documented.

## Audit

Test:

- application cannot update/delete audit history;
- operator cannot read audit log;
- administrator can read but not mutate history through normal interface;
- broken audit collector blocks sensitive actions;
- hash-chain/checkpoint verification detects alteration;
- notification fires on audit interruption.
- OPEN/REOPEN Key Service release fails without the required valid pre-action receipt;
- receipts cannot be replayed across operator, report, operation, state version, or lease generation;
- REQUESTED/AUTHORIZED/COMPLETED/FAILED events represent crash and failure outcomes truthfully;
- full reopening/export operator notes never enter permanent audit;
- hash-chain verification detects mutation;
- independent checkpoints detect suffix truncation, gaps, and audit cessation.
- collector-controlled 365-day expiry cannot be accelerated by application/operator roles and preserves the approved checkpoint evidence.
- RFC 8949 deterministic CBOR and closed-schema rejection use published vectors
  and reject alternate encodings, types, sizes, unknown fields, and trailing data;
- COSE Sign1/Ed25519 verification rejects altered payloads, signatures, key IDs,
  algorithms, content types, and key substitution;
- RFC 9162 roots/inclusion/consistency and RFC 9942 receipts match published
  vectors and reject malformed or context-mismatched proofs;
- no receipt bytes are released before the audit event and receipt commit is
  durably complete, including every injected crash point;
- 20–100 synchronized retries over multiple PostgreSQL connections and
  processes produce one leaf and one byte-identical receipt for the same exact
  request, while mismatched retries and reused nonces fail closed;
- mutation, middle deletion, duplicate index, suffix truncation, fork, rollback,
  checkpoint-key substitution, and cessation are detected;
- proposed maximum merge delay, heartbeats, witness liveness, and fail-closed
  issuance cutoff are tested with a controlled clock;
- signer rotations and event/proof retention preserve historical verification
  without granting early-expiry or signing authority to application roles.

SQLite, a single process, an application cache/lock, or an in-memory collector
does not satisfy audit concurrency and durability acceptance.

## Emergency export

Test:

- export requires OPEN state;
- export requires reason;
- export requires CAPTCHA;
- export requires step-up MFA;
- admin alert occurs;
- manifest hashes match exported bytes;
- manifest signature verifies;
- final artifact is encrypted to configured organization key;
- no plaintext temporary artifact persists unexpectedly;
- audit stores artifact hash but not content.
- step-up authorization cannot be reused across export/finalization or tickets;
- permanent audit contains only the reason code, not the full protected note;
- mandatory audit/notification precondition failure blocks artifact release;
- crash/timeout cleanup removes plaintext temporary package components;
- accepted residual risk is documented and not misrepresented as prevented.
- the exact deterministic-CBOR request descriptor binds note, reason, immutable
  content envelopes, operator/session/lease/state, and active recipient/signer;
- only the closed uncompressed `ustar` profile and fixed safe member order,
  paths, metadata, sizes, padding, and end marker are accepted;
- RFC 8785 manifest bytes, detached tagged COSE Sign1/Ed25519, external key
  registry, and every exact content hash verify independently;
- binary `age` v1 contains exactly one native X25519 recipient and rejects
  passphrase, plugin, SSH, hybrid, multiple-recipient, armored, and unknown
  profiles for version 1;
- export/export, export/finalization, export/deletion, stale worker, lease
  expiry, duplicate request, and delivery replay races have one fenced winner;
- no plaintext package/member or private recipient key appears in filesystem,
  swap, core, queue, log, audit, alert, trace, proxy, or backup inspection;
- the organization-side canary decrypt/signature/content ceremony succeeds,
  while the production platform demonstrably lacks the recipient private key;
- encrypted staging is never released before the durable COMPLETED receipt and
  one-shot POST delivery cannot be resumed, replayed, or served after expiry.

## Recovery and Response-DEK

Test:

- Recovery Secret is never the sole material sufficient to decrypt a restored Response Note ciphertext;
- first valid read uses server time and fixes expiry at +72 hours;
- repeated valid reads work only inside the approved 72-hour window;
- Response-DEK destruction invalidates recovery state and leaves restored ciphertext unusable;
- server-authoritative expiry denies use even while replica/key-material/ciphertext cleanup is retrying;
- old Response-DEK replicas, snapshots, rollback, or disaster recovery cannot resurrect an expired response;
- concurrent first reads establish one immutable `first_read_at`/expiry and later reads cannot extend it;
- server never emits the Recovery Secret a second time;
- verifier key/material is purpose-separated and never logged.
- XChaCha20-Poly1305 key/nonce/tag sizes, official vectors, combined-mode length,
  and pinned library behavior match the approved profile;
- deterministic-CBOR AAD/envelope bytes reject unknown/alternate schemas and
  any cross-report, response, finalization, or key-handle substitution;
- canonical NFC/LF/UTF-8 framing rejects invalid scalars, invalid lengths,
  nonzero padding, malformed UTF-8, and over-limit text;
- all allowed Response Note lengths produce one constant ciphertext length;
- the Django/application boundary never receives or persists Response-DEK
  material and exposes no general decrypt/unwrap operation;
- provisional create, PostgreSQL `FINALIZING` commit, verification, activation,
  and every injected crash point remain idempotent and reporter-invisible;
- 20–100 synchronized first-read attempts across PostgreSQL connections and
  processes establish one immutable expiry before any decrypt;
- Key Service expiry remains authoritative while database/workers/cleanup are
  unavailable, stale, delayed, or rolled back.

## Roles and capabilities

Test:

- Application Administrator cannot read reports, obtain DEKs, invoke unwrap/decrypt, or impersonate an operator through reset/recovery/session functions;
- Infrastructure / Key Custodian does not inherit operator, application-administrator, audit-reader, or report-reader privileges;
- Application Administrator authentication requires the approved strong MFA and cannot reset/enroll an operator factor under administrator control;
- Reporter Gateway cannot invoke general decrypt/unwrap for existing SEALED reports;
- Key Service authorization is rejected for the wrong role, operation, report, state, lease generation, or receipt.

For `33_OPERATIONAL_ACCESS_AND_WORKSTATION_HARDENING.md`, also verify on the
exact physical production candidates:

- Ubuntu image, Secure Boot, LUKS2, no swap/hibernate/dumps, AppArmor, firewall,
  firmware, IOMMU, patch deadlines, signed inventory, and drift quarantine;
- Operator/Admin/Custodian workstations, networks, device certificates,
  RP/origins, cookies, accounts, hardware factors, and routes reject every
  cross-role use;
- Firefox ESR policies block alternate profiles, extensions, telemetry, sync,
  persistence, PDF, developer tools, print, clipboard, screenshot, drag/drop,
  external protocols, and ordinary downloads;
- ephemeral profile, safe views, cookies, cache, clipboard, and export `tmpfs`
  disappear after logout, crash, lock failure, disconnect, power loss, and
  reboot without swap/core/thumbnail/index leakage;
- Operator and Administrator idle/absolute/one-session/revocation rules are
  server-authoritative and never extend ReportLease or step-up;
- administrative version-2 step-up rejects cross-actor/device/session/
  operation/target/artifact/batch replay and cannot grant report access;
- export transfer accepts only the exact encrypted artifact/capability/hash/
  media and never exposes the private recipient key;
- custodian quorum, 15-minute hardware-backed SSH certificates, command
  wrappers, break-glass expiry, infrastructure restore, and non-resurrection
  work at every crash/failure boundary.

## WebAuthn, step-up, and credential lifecycle

Test:

- exact RP ID/origin, challenge, ceremony type, UV/UP, signature, COSE
  algorithm, AAGUID/attestation, device-bound backup flags, credential ownership,
  and extension validation;
- challenge and StepUpAuthorization entropy, 120-second non-sliding expiry,
  single use, and absence from URLs/logs/browser persistence;
- deterministic-CBOR HMAC artifact binding rejects any byte or
  operator/session/operation/report/lease/version change;
- synchronized multi-process consumption has one database winner and resumes
  only the immutable committed workflow after crashes;
- operator/admin credential, RP, session, cookie, role, and deployment
  separation prevents administrator impersonation;
- two-key enrollment, lost-one replacement, lost-all in-person recovery,
  separate-role quorum, 24-hour delay, and unavailable-quorum denial;
- SMS, email, TOTP, recovery links/codes, password-only, remote help-desk, and
  administrator-only fallback paths do not exist.

## CAPTCHA

Test:

- all challenge resources and validation are self-hosted;
- mandatory operations fail closed when challenge generation/verification is unavailable;
- no-JavaScript challenges are single-use, expire according to the approved policy, and cannot be replayed;
- neither CAPTCHA path uses IP/device fingerprinting or third-party tracking;
- Tor Browser Safest remains usable after the no-JavaScript technology is approved.

Current Stage A evidence additionally tests that the inert no-JavaScript
CAPTCHA descriptor accepts only the approved identifier, answer, expiry,
cleanup, state, purpose, PNG-bound, anonymous bucket, and open-gate metadata.
Its exact-source policy rejects generation, persistence, answer validation
success paths, network-identity binding, third-party CAPTCHA, endpoint
enablement, dynamic behavior, and source echoing. These tests are source-level
evidence only and do not enable the Challenge Service.

## Alerts

Test:

- audit gaps/cessation, persistent ciphertext deletion failure, and Emergency Export trigger the approved alert path;
- alert payloads contain only allowlisted controlled metadata;
- alert transport failure follows the approved retry/fail-closed behavior without leaking sensitive data.

For `31_ADMINISTRATOR_ALERT_PROTOCOL.md`, also verify:

- the Alert Service never acknowledges before the inbox row and fixed-template
  SMTP queue item commit durably;
- identical/conflicting concurrent retries create one logical alert and cannot
  extend or rewrite its accepted time;
- Emergency Export fails before authorization consumption or artifact work when
  durable alert acceptance is unavailable;
- deletion retry, key denial/destruction, and audit fail-closed deadlines do not
  wait for alert delivery;
- SMTP/console outages, acknowledgement races, retention failure, and restarts
  preserve the exact alert state and escalation schedule;
- prohibited sentinels never reach alerts, source outboxes, SMTP, logs, metrics,
  traces, or errors.

## Browser caching

Test headers and browser behavior for:

- reporter secret display page;
- operator report page;
- Response Note retrieval.

Verify no-store behavior and absence of intentional local persistence.

## Stage A inert reporter surface

While only the owner-approved inert Stage A is enabled, statically verify
without importing or rendering the target source that:

- the development `INSTALLED_APPS` and `MIDDLEWARE` lists remain exact and do
  not add authentication, administrator, session, message, or protected-domain
  capability;
- the root URL configuration contains exactly the read-only reporter home and
  cannot be extended through a later mutation;
- the reporter view remains exactly one safe-method-only template render with
  no request-derived context, input handling, persistence, cookies, redirect,
  or additional endpoint behavior;
- the response middleware retains the exact no-store, CSP, referrer,
  permissions, cross-origin, and cross-domain header profile and performs no
  request logging or other side effect;
- the landing template contains only the closed passive tag, attribute, meta,
  first-party stylesheet, and Django-static-directive profile;
- form, input, script, iframe, link, image, event/style attribute, template
  variable/include, processing instruction, malformed nesting, and external or
  active URL scheme injections fail closed;
- CSS `@import`, `@font-face`, `url()`, legacy expression/behavior/binding, and
  JavaScript-scheme constructs fail closed;
- missing, unreadable, malformed, dynamic, mutated, and out-of-root policy
inputs return controlled violations without source excerpts.

The reporter view and middleware checks compare their executable AST against
the reviewed inert profile. Comments may change without altering that profile;
any executable change requires an explicit reviewed policy update.

Passing this source policy is not browser, runtime, process, network, or
deployment proof and cannot close any external gate.

## Stage A administrative step-up source conformance

While the administrative step-up-v2 implementation remains an inert structural
foundation, statically verify without importing or executing the target that:

- the target path, imports, protocol version `2`, and `120 * 1000` millisecond
  lifetime remain exact;
- the complete top-level member set, immutable slotted class profiles, false
  capability properties, and validator bodies remain exact;
- only the closed constructor, validator, type-check, length, and timing calls
  are present;
- nested imports, dynamic constructs, added members, persistence, network,
  cryptographic, file, logging, and authorization behavior fail closed;
- missing, unreadable, malformed, and out-of-root inputs return controlled,
  content-free violations.

Passing this policy proves only exact source conformance. It does not prove
administrator identity, WebAuthn, session/device binding, persistence,
single-use consumption, concurrency, or production readiness.

## Stage A recovery descriptor source conformance

While recovery implementation remains blocked behind independent review and
dependent production gates, statically verify without importing or executing
the target that:

- the target path, imports, protocol version, credential sizes, encoded
  lengths, alphabets, encoding names, roles, verifier tag size, and domain label
  remain exact;
- immutable slotted descriptor classes return only content-free structural
  evidence and expose no credential text, decoded bytes, verifier tag, key,
  lookup, endpoint, persistence, or authorization field;
- validators reject non-string, malformed, non-canonical, padded, wrong-length,
  Unicode, alternate-alphabet, or role/encoding-mismatch inputs with a generic
  controlled error that echoes no supplied value;
- generation, random sources, HMAC/hash computation, constant-time comparison,
  persistence, logging, networking, file access, Django integration, dynamic
  imports, `eval`, `exec`, and success authorization behavior fail closed;
- missing, unreadable, malformed, and out-of-root inputs return controlled,
  content-free violations.

Passing this policy proves only exact source conformance. It does not implement
credential generation, verifier creation/verification, recovery lookup,
Response-DEK use, persistence, endpoint behavior, or production readiness.

## Stage A response crypto descriptor source conformance

While Response Note cryptography remains blocked behind independent review and
dependent production gates, statically verify without importing or executing
the target that:

- the target path, imports, protocol version, algorithm ID/name, content-profile
  ID/name, key size, nonce size, tag size, frame size, ciphertext/tag size,
  scalar/UTF-8 limits, immutable context sizes, AAD purpose, and key-operation
  sequence remain exact;
- immutable slotted descriptor classes expose only static profile shapes and no
  Response Note text, plaintext bytes, ciphertext bytes, nonce bytes, AAD bytes,
  real key handle, Response-DEK material, receipt, recovery authorization, or
  state field;
- validators reject unknown algorithms, alternate profiles, wrong sizes, wrong
  operation order, added operations, string-only operation lists, and malformed
  objects with a generic controlled error that echoes no supplied value;
- canonicalization, Unicode normalization, frame construction, deterministic
  CBOR, AEAD encryption/decryption, Key Service calls, persistence, logging,
  networking, file access, Django integration, dynamic imports, `eval`, `exec`,
  and success authorization behavior fail closed;
- missing, unreadable, malformed, and out-of-root inputs return controlled,
  content-free violations.

Passing this policy proves only exact source conformance. It does not implement
Response Note canonicalization, frame or envelope parsing, encryption,
decryption, Response-DEK lifecycle operations, recovery authorization,
persistence, endpoint behavior, or production readiness.

## Stage A response text descriptor source conformance

While Response Note finalization remains blocked behind independent review and
dependent production gates, statically verify without importing or executing
the target that:

- the target path, imports, profile version, normalization, line-ending,
  encoding, content kind, scalar limit, UTF-8 byte limit, forbidden codepoints,
  forbidden characters, and no-link marker sequence remain exact;
- immutable slotted descriptor classes expose only static profile shapes and no
  submitted text, normalized text, canonical bytes, artifact digest, preview,
  server-side draft, frame, receipt, report state, persistence, or endpoint
  field;
- validators reject non-string, NUL, surrogate, HTML-marker, link-marker,
  over-scalar-limit, over-byte-limit, wrong-profile, and malformed objects with
  a generic controlled error that echoes no supplied value;
- digesting, byte freezing, frame construction, persistence, logging,
  networking, file access, Django integration, step-up binding, finalization,
  dynamic imports, `eval`, `exec`, and success authorization behavior fail
  closed;
- missing, unreadable, malformed, and out-of-root inputs return controlled,
  content-free violations.

Passing this policy proves only exact source conformance. It does not implement
the final preview, canonical byte production, artifact digest binding,
Response Note staging, persistence, endpoint behavior, finalization, or
production readiness.

## Stage A response schema descriptor source conformance

While deterministic CBOR and Response Note envelope handling remain blocked,
statically verify without importing or executing the target that:

- the target path, imports, AAD schema field order, envelope schema field order,
  field names, primitive categories, exact public constants, and fixed byte-size
  metadata remain exact;
- immutable slotted descriptor classes expose only schema metadata and no
  actual report ID, response ID, finalization ID, key handle, nonce, AAD bytes,
  ciphertext, plaintext, receipt, recovery authorization, or state field;
- validators reject wrong schema kind, wrong version, reordered fields, missing
  fields, extra fields, value-bearing byte fields, list inputs, and malformed
  objects with a generic controlled error that echoes no supplied value;
- deterministic-CBOR encoding/parsing, cryptographic authentication,
  ciphertext handling, persistence, logging, networking, file access, Django
  integration, Key Service calls, dynamic imports, `eval`, `exec`, and success
  authorization behavior fail closed;
- missing, unreadable, malformed, and out-of-root inputs return controlled,
  content-free violations.

Passing this policy proves only exact source conformance. It does not implement
deterministic CBOR, envelope parsing, cryptographic authentication,
Response-DEK lifecycle operations, recovery authorization, persistence,
endpoint behavior, or production readiness.

## Dependency/security checks

During inert Stage A, CI must run `python -m architecture_checks .`. The
aggregate static gate includes repository-hygiene checks that:

- inspect only tracked path names and `.gitignore` rules;
- reject tracked local databases, logs, virtual environments, secret/config
  material, export artifacts, temporary workspaces, quarantine areas, user
  media, collected static output, and cache/test artifacts;
- preserve the reviewed `.gitignore` baseline for local-sensitive artifacts;
- fail closed when `.gitignore` or tracked-file enumeration is unavailable;
- return controlled, content-free violations without reading or echoing file
  contents.

This is repository hygiene only. It is not a replacement for secret scanning,
dependency vulnerability scanning, code review, deployment validation, or
incident-response handling of sensitive material.

Before release:

- dependency vulnerability scanning;
- Django deployment checks;
- static analysis;
- secret scanning;
- container/image scanning if containers used;
- manual review of security-sensitive code.
