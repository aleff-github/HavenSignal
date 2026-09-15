# Security-service review and proof work packet

Prepared: 2026-09-14. Status: preparation complete; service proofs and independent
review NOT COMPLETE. This packet turns Phase 2 of the
[alpha checklist](ALPHA_DEVELOPMENT_TODO.md) into bounded work items. It grants
no protected application capability and changes no approved protocol.

## Inputs and review boundary

Review the [security baseline](01_SECURITY_BASELINE.md),
[service interfaces](19_SECURITY_SERVICE_INTERFACES.md),
[Audit v1](23_AUDIT_RECEIPT_AND_TRANSPARENCY_PROTOCOL.md),
[Key Service acceptance specification](27_KEY_SERVICE_ACCEPTANCE_AND_NON_RESURRECTION_POC.md),
and [pre-code gate](34_PRE_CODE_SECURITY_GATE.md) together. Response and report
formats remain governed by docs/24 and docs/26. The Stage A exit record is
metadata evidence only and does not satisfy any service proof below.

Use synthetic data in an isolated test environment. No proof may accept real
reports, reuse deployment secrets, release a receipt to an application, or
enable an unavailable adapter. Production-equivalent destructive Key Service
tests need a dedicated disposable topology and an explicit inventory of every
resource they can destroy.

## P2-01 — Complete the exact audit profile for review

Requirements: SEC-LOG-001..012, SEC-ANON-003, SEC-AUTH-005..007.

The following are concrete review inputs, not proposed defaults:

- Docs/23 names 40 event types but requires a per-event matrix of caller,
  actor, object, operation, source state, required/null fields, reason/outcome
  values, and authorization eligibility. Produce that complete matrix and
  closed registries before a collector accepts requests.
- `REPORT_KEY_DESTROYED` has a five-minute authorization window only before
  response publication. `security_interfaces/audit_descriptors.py` explicitly
  denies this context because its operation profile is incomplete. The matrix
  must distinguish this use from ordinary deletion outcomes.
- Docs/23 fixes the acceptance-receipt content type, but describes checkpoint
  and RFC 9942 receipt content types without exact string values. Record the
  reviewed values before claiming byte-level interoperability for those
  artifacts.
- The clock-skew ceiling is explicitly a deployment review item. Record the
  clock source, bounds, rollback behavior, and associated rejection tests;
  do not introduce a caller-selected tolerance.

Deliverable: a reviewed profile matrix, exact artifact schemas, and a decision
record identifying affected protocol sections and reviewer findings. Missing
rows or undecided fields remain blocking for the affected implementation.

## P2-02 — Produce reproducible interoperability evidence

The first [bounded wire corpus](../proofs/audit_vectors/README.md) passed on
2026-09-15: published CBOR/Ed25519/COSE examples plus 40 synthetic
acceptance-receipt cases, independently verified in Python and JavaScript.
The full deliverable below remains open. The minimal public COSE Key map used
to derive the fixture key ID is explicitly a test choice; the production
parameter set for that serialization also needs review.

Depends on P2-01 for application-specific profiles and on the independent
review gates of docs/21, docs/23, docs/24, and docs/26 for protected integration.

- Pin mature CBOR/COSE/cryptographic implementations separately from the
  application's current runtime dependencies. Record versions and hashes.
- Start with published RFC test vectors, then produce exact synthetic request,
  event, acceptance-claim, protected-header, signature-input, signed-receipt,
  checkpoint, inclusion, and consistency bytes.
- Verify the frozen bytes using a second implementation. A generator checking
  its own output is insufficient interoperability evidence.
- Include non-minimal CBOR, indefinite lengths, wrong types, unknown or extra
  fields, altered signatures/payloads, wrong key IDs/content types, invalid
  inclusion/consistency paths, and wrong event/context bindings.
- Keep standard-vector validity distinct from application-profile acceptance
  and from authorization. A valid signature must not authorize an operation.

Deliverable: a versioned corpus, reproducible commands, expected rejection
results, provenance, cross-implementation results, and review findings. No
application signing credentials or production private keys enter the corpus.

## P2-03 — Exercise an isolated Audit Service proof

Requirements: SEC-LOG-004, SEC-LOG-009..012, SEC-ACCESS-010..015.

After the exact profile is reviewable, freeze the collector/store, separate
receipt and checkpoint signers, witness, identities, clocks, and durability
configuration. Test at least these boundaries:

| Scenario | Required observation |
|---|---|
| Failure after signing, before commit | No receipt escapes; no committed event is claimed. |
| Commit succeeds, reply is lost | An identical retry returns the same event and receipt without a second leaf or extended validity. |
| 20–100 synchronized identical or conflicting requests | Database-authoritative replay constraints produce the specified single outcome. |
| Missing/altered/expired receipt or stale caller/state/lease | The protected-service test consumer denies the operation. |
| Witness failure, late inclusion, fork, truncation, clock rollback | Issuance stops and controlled failure evidence matches docs/23 deadlines. |
| Signing-key rotation and retention | Historical verification survives without granting signing or early-deletion authority. |

Deliverable: reproducible multi-process and fault-injection runs with exact
expected/actual results. In-memory mocks and Stage A PostgreSQL tests do not
prove audit durability, witness independence, or protected-action gating.

## P2-04 — Evaluate a Key Service candidate without assuming approval

Requirements: SEC-KEY-001..007, SEC-DEL-004, SEC-ROLE-001..004.

OpenBao is only the existing candidate named in docs/27. Before provisioning,
produce a capability/topology inventory showing where per-object key material
can exist, including snapshots, journals, stale replicas, caches, and retained
seal/wrapping/recovery material. Reject an incompatible design early; product
selection must not weaken non-resurrection.

For a candidate that passes this design screen, freeze the full disposable
production-equivalent topology and execute docs/27's canary procedure for both
Report-DEK and Response-DEK. Cover destruction propagation, delayed replicas,
storage-level copies, restore/rollback combinations, privileged operational
paths, upgrade, rotation, node replacement, and disaster recovery. Include
20–100 concurrent clients and failures at each acknowledged transition.

Deliverable: the signed, content-free evidence package specified by docs/27,
with inventory hashes and a PASS/FAIL for every matrix cell. One successful
post-destruction decrypt is FAIL; a missing test or independent review prevents
acceptance. The package excludes canary material, raw logs, and secrets.

## P2-05 — Record independent findings before integration

Deliverable: named review scope, reviewed artifact versions/hashes, findings,
severity, remediation evidence, reviewer outcome, and unresolved limitations.
No external review has been performed or commissioned by preparing this packet.

Update docs/12, docs/13, docs/34, and the alpha checklist only for the gates
actually satisfied. Keep public submission, operator authentication, recovery,
content storage, key operations, and protected execution disabled until their
own dependencies pass. The next delivery milestone is an audited synthetic
text flow; this packet itself does not implement that flow.
