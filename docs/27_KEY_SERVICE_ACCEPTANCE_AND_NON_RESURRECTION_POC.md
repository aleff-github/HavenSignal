# 27 — Key Service Acceptance and Non-Resurrection PoC

## Status

**PROPOSED ACCEPTANCE SPECIFICATION — consolidated project-owner and independent
cryptographic/infrastructure review required. No Key Service product or topology
is approved. A real release-blocking PoC must pass before protected code is
enabled.**

This document does not select OpenBao, an HSM, a cloud KMS, storage backend, or
vendor. It defines the minimum capabilities, trust separation, service
authentication, durability semantics, destructive test matrix, evidence, and
binary acceptance criteria a candidate must satisfy.

## Governing requirements

- `SEC-CONF-001..008`;
- `SEC-LOG-004`, `SEC-LOG-009..012`;
- `SEC-ACCESS-010..015`;
- `SEC-DEL-001..006`;
- `SEC-KEY-001..007`;
- `SEC-ROLE-001..004`;
- `SEC-RESPONSE-002..008`;
- `SEC-FINALIZE-001..006`.

The application cryptographic formats in `docs/24` and `docs/26` are separate
from this product decision. Passing format review does not make a key store
acceptable; passing this PoC does not approve an application protocol.

## Non-negotiable outcome

For each Report-DEK and Response-DEK, the selected system must provide:

1. independent random creation and non-exportable in-service use;
2. live availability only inside the approved key trust domain;
3. narrowly authenticated, role/operation/object/state/receipt-bound use;
4. immediate denial when state, time, audit, or policy is uncertain;
5. irreversible, monotonic destruction across every supported live replica;
6. no restoration through an earlier database, disk, VM, volume, Raft, HSM,
   KMS, application, configuration, or disaster-recovery snapshot;
7. no reconstruction by combining retained ciphertext/backups with retained
   infrastructure keys, seal keys, wrapping keys, quorum shares, logs, or
   exported material.

Catastrophic loss of all active per-object keys is accepted. A candidate that
requires restorable historical per-object key backup is incompatible, even if
that backup improves availability.

## Required trust domains

Production separates at least:

- Key Service API/policy process;
- live per-object key storage/cryptographic module;
- State Authority queried for current server state/version/lease/expiry;
- Audit receipt verifier using public verification material only;
- Infrastructure / Key Custodian control plane;
- application callers with distinct Reporter, Recovery, Operator, Workflow, and
  Export service identities;
- independent audit/witness and alert systems.

Key Service administration does not grant Operator/Application Administrator
sessions, report selection, Ticket ID lookup, audit-reader authority, or a
general decrypt interface. Application/database administration does not grant
Key Service control or key use.

Root/recovery/seal authority, if the product has it, requires a documented
multi-person ceremony and is absent from normal runtime/application roles. It
must not provide a supported path to restore a destroyed per-object key.

## Network and workload authentication proposal

The supported profile uses mutually authenticated TLS with a private,
offline-rooted service PKI and exact workload identities. Requirements:

- TLS 1.3 only under the final cipher/module review;
- separate certificates and policy for every caller profile and instance;
- exact URI/DNS identity allowlists, never caller Host/header claims;
- certificates valid for at most 24 hours and automatically rotated through the
  approved workload-identity channel;
- private keys non-exportable where supported and unavailable to application
  administrators;
- no shared client certificate, static root token, query-string credential, or
  developer credential in production;
- no public ingress and default-deny network policy;
- bounded request/response sizes and controlled timeouts;
- certificate revocation/expiry fails closed.

If a product additionally requires an application token, it must be minted from
the authenticated workload identity, valid at most 15 minutes, memory-only,
non-renewable beyond the workload certificate, audience/profile scoped, and
incapable of broad list/export/administration. Product tokens cannot replace
mTLS identity.

Exact CA, workload-identity product, certificate profile, cipher suite, and
revocation mechanism remain deployment-review items.

## Server-authoritative policy inputs

The Key Service never trusts caller claims alone for report state, lease,
expiry, or audit. Before a protected operation it must:

1. authenticate the caller workload and map it to one fixed capability profile;
2. validate the exact typed operation envelope and idempotency/action nonce;
3. synchronously query the authenticated State Authority for current
   object/state/version/lease/generation/expiry where applicable;
4. validate exact event bytes and the signed durable receipt under `docs/23`;
5. enforce its own monotonic key state and trusted clock;
6. verify operation-specific artifact binding where required;
7. deny on any mismatch, rollback, stale replica, timeout, ambiguity, or
   unavailable dependency.

The State Authority response is not cached beyond the one operation. A stale
positive cache, caller-supplied timestamp, or previously valid receipt cannot
override current destroyed/expired/fenced state.

## Capability profiles

| Caller | Allowed | Explicitly denied |
|---|---|---|
| Reporter Gateway | Create provisional Report-DEK and encrypt only objects for one currently owned new attempt | Existing-key use, decrypt, list, export, Response-DEK, destroy active report |
| Submission reconciler | Verify/activate exact SEALED binding or destroy definitive aborted provisional key | Plaintext, arbitrary selection, existing active decrypt |
| Operator Console | In-service report-text decrypt for exact current OPEN/REOPEN lease | Key bytes, attachment original, response key, arbitrary report/list |
| File Sandbox | One original attachment stream for one approved job/destination | Report text, other objects, key bytes, reusable capability, network redirect |
| Recovery Gateway | One in-service Response Note decrypt inside armed read window | Report key/content, Response-DEK bytes, expiry extension, enumeration |
| Workflow Coordinator | Exact response create/verify/activate/expire and fenced DEK destruction | Interactive plaintext/read, key export, report selection, reverse destruction |
| Emergency Export Worker | Exact current report plaintext stream for one authorized export | Key bytes, arbitrary reports, destruction/finalization, reusable access |
| Infrastructure / Key Custodian | Operate health, quorum, software/module/config lifecycle under ceremony | Application-level report selection/decrypt, operator/admin session, key export |

Every omitted operation is denied. Product-native list, backup, export, import,
restore, soft-delete-restore, convergent encryption, plaintext data-key, and
general transit/decrypt endpoints must be disabled or unreachable for
per-object key roles.

## Per-object key state machine

```text
PROVISIONAL -> ACTIVE -> EXPIRY_ARMED -> DESTROYING -> DESTROYED
      |          |             |
      +----------+-------------+-> DESTROYING
```

- `PROVISIONAL` is usable only for exact create/encrypt/verify staging.
- `ACTIVE` allows only policy-approved current operations.
- `EXPIRY_ARMED` has one immutable not-after time and cannot return to ACTIVE.
- `DESTROYING` denies every use while replication/confirmation resolves.
- `DESTROYED` is terminal and has no restore/import/recreate edge for the same
  internal object/finalization identity.

Transitions use monotonic versions, database/storage compare-and-swap or
equivalent consensus, idempotency uniqueness, synchronous durability, and
server time. A stale replica cannot serve a read/use operation independently.

## Backup and snapshot prohibition

No supported backup/snapshot may contain a representation that, combined with
retained material, makes an old per-object DEK usable. This covers:

- plaintext, wrapped, encrypted, derived, sealed, cached, journaled, or exported
  key objects;
- Raft/log/FSM snapshots and compaction artifacts;
- filesystem, block-volume, VM, container, memory, database, HSM, KMS, or cloud
  snapshots;
- replication queues and a node isolated before deletion;
- seal/root/wrapping keys, Shamir/recovery shares, HSM backups, and configuration
  exports;
- support bundles, crash dumps, swap, hibernation, logs, metrics, and traces.

Infrastructure configuration and public verification material may be backed up
only when the combined-backup test proves they cannot restore per-object keys.
If the product cannot separate configuration recovery from DEK resurrection,
the product is rejected.

## OpenBao candidate assessment

OpenBao remains an unevaluated candidate, not the baseline selection. Its
official integrated-storage documentation describes replicated persistent
BoltDB state, automatic Raft snapshots, and backup/restore workflows. Its
Transit API also exposes key backup where configured and a reversible soft
delete/restore operation.

Therefore a normal OpenBao Transit key stored in integrated Raft must be
presumed incompatible with this project's non-resurrection requirement until a
real topology demonstrates that restoring any supported pre-destruction
snapshot cannot make the canary decryptable. Merely setting
`deletion_allowed`, calling hard delete, disabling the soft-delete endpoint, or
asserting that production staff will not restore an old snapshot is not proof.

The PoC may reject OpenBao. It must not weaken `SEC-KEY-002..004` to preserve a
preferred product choice.

## Release-blocking PoC environment

The test uses no real report data. It deploys the exact candidate versions,
modules, HSM/KMS/seal, node count, storage, replication, clocks, workload PKI,
policies, backup tooling, and recovery runbooks intended for production.

Before testing, freeze and hash:

- software/container/firmware/module versions and provenance;
- every configuration and policy;
- network identity and authorization matrix;
- storage/replication/snapshot/backup settings;
- seal/wrapping/HSM/KMS key inventory and custody rules;
- supported failure, upgrade, scale, restore, and disaster-recovery procedures.

Any production-relevant difference invalidates the result until retested.

## Canary procedure

For each key class (`Report-DEK`, `Response-DEK`) and each supported topology:

1. create a random canary plaintext outside the product;
2. create the per-object key through the exact application capability;
3. encrypt the canary under the exact `docs/24` or `docs/26` protocol;
4. verify authorized use and every forbidden caller/operation;
5. capture every backup/snapshot/artifact that the supported procedures can
   produce before destruction;
6. isolate one live replica before destruction and delay its messages;
7. start destruction while injecting leader, network, disk, process, quorum,
   and response-loss failures at every boundary;
8. confirm all live replicas reach terminal denial and return durable evidence;
9. reconnect the stale replica and prove it cannot serve or reintroduce the key;
10. restore each pre-destruction artifact separately and in every meaningful
    combination with retained infrastructure/seal/wrapping material;
11. replay old state/receipts/capabilities, roll clocks backward/forward, and
    attempt old-node leadership/quorum formation;
12. prove the original canary ciphertext cannot be decrypted through any
    supported or privileged operational path;
13. repeat after upgrade, node replacement, seal/key rotation, and the complete
    disaster-recovery runbook.

The test must include storage-level copies taken without application knowledge,
not only product-exported backups.

## Authorization and negative-capability tests

Automated policy tests attempt every operation with every identity, including:

- wrong caller profile/instance;
- valid caller with wrong operation/object/state/version/lease/generation;
- missing, altered, expired, replayed, or context-mismatched audit receipt;
- stale StepUpAuthorization/artifact binding;
- caller-selected key handle, nonce, algorithm, destination, or expiry;
- list/export/backup/import/restore/soft-restore/general decrypt endpoints;
- administrator, database, deployment, monitoring, backup, and support
  credentials;
- combined credentials that normal role assignment could accidentally grant.

Only explicit matrix cells may succeed. Infrastructure health/maintenance
interfaces return no per-object identifiers, plaintext, keys, or content-derived
values.

## Durability and concurrency tests

At least 20–100 synchronized clients across processes/nodes exercise create,
activate, use, arm-expiry, and destroy. Tests prove:

- one logical key and byte-identical create result per idempotency context;
- mismatched retry and reused action nonce fail closed;
- no use after `DESTROYING` begins or hard expiry occurs;
- one immutable expiry and no sliding/rearm race;
- stale followers never authorize local reads;
- acknowledged transitions survive power loss of the acknowledging node and
  the documented fault threshold;
- unknown responses resolve idempotently without recreation;
- quorum loss produces unavailability, never weaker local service.

## Evidence package

The PoC produces a signed, content-free evidence package containing:

- frozen inventory/configuration hashes;
- test IDs and controlled expected/actual result codes;
- node/replica/backup/restore matrix;
- durable audit/checkpoint references;
- key-state transitions using random test identifiers only;
- proof that canary decryption failed after every restoration attempt;
- deviations, unresolved observations, and reviewer signatures;
- explicit PASS/FAIL for every acceptance criterion.

It contains no real secrets, private keys, canary plaintext/ciphertext after the
test, tokens, raw logs, or unrestricted configuration secrets.

## Binary acceptance criteria

A candidate is approved only if all conditions pass:

- every authorized use works before destruction under the exact policy;
- every forbidden edge is denied;
- every acknowledged key transition meets the durability/fault claim;
- hard expiry and `DESTROYING` deny immediately;
- no stale replica, snapshot, rollback, restore, disaster-recovery, combined
  backup, or privileged normal operation makes a destroyed key usable;
- normal Application Administrator and Infrastructure / Key Custodian roles
  cannot select/decrypt reports or export keys;
- all evidence is complete and independently reviewed;
- no CRITICAL unresolved finding exists.

One successful post-destruction decrypt is an unconditional FAIL. A partial,
untested, vendor-asserted, policy-only, or mock result is not acceptance.

## Failure behavior in production

| Failure | Required behavior |
|---|---|
| State/Audit/clock/policy dependency unavailable | Deny protected operation |
| Quorum/leader/storage durability unavailable | No acknowledged create/use/destroy transition |
| Replica stale or rollback detected | Quarantine node, deny, alert |
| Destruction outcome unknown | Deny use and resume forward; never recreate |
| Snapshot/restore includes usable destroyed key | Remove service from production; CRITICAL incident |
| Workload identity/token compromise | Revoke profile, deny, rotate, investigate without broad fallback |
| HSM/KMS/seal unavailable | Fail closed; accept active-report loss if permanent |
| PoC evidence incomplete or topology changed | Approval invalid; retest before enablement |

## Consolidated decisions awaiting the pre-code gate

1. candidate-neutral acceptance criteria and willingness to reject OpenBao;
2. mTLS workload identity, 24-hour certificates, optional 15-minute
   identity-minted product tokens, and no shared/root runtime credential;
3. synchronous State Authority and audit-receipt verification with no stale
   positive cache;
4. the exact capability matrix and forward-only key state machine;
5. prohibition of every historical/combined per-object-key backup;
6. the destructive canary, stale-replica, snapshot/rollback/DR test matrix and
   binary no-exception acceptance rule.

Actual product selection remains blocked until the PoC passes in the exact
production-equivalent environment and receives independent review.

## External design references

- [OpenBao — Integrated Storage](https://openbao.org/docs/internals/integrated-storage/)
- [OpenBao — Raft storage backend](https://openbao.org/docs/configuration/storage/raft/)
- [OpenBao — Transit secrets engine](https://openbao.org/docs/secrets/transit/)
- [OpenBao — Transit API](https://openbao.org/docs/api/secret/transit/)
- [OpenBao — Seal and unseal](https://openbao.org/docs/concepts/seal/)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
