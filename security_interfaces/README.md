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
