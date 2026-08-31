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

The package initializer is also locked by a non-executing exact-AST policy so
its reviewed re-export surface cannot gain a production service, side effect,
dynamic behavior, or widened public capability without an explicit policy
update. Passing this initializer policy is source-conformance evidence only.
