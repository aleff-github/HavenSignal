# 04 — Cryptographic Model

## Principles

- No custom cryptographic algorithms or protocols.
- Use mature, well-reviewed libraries.
- Separate encrypted data from key material.
- Use independent per-report data-encryption keys (DEKs).
- Design deletion around destruction/non-recoverability of the DEK.
- Avoid a single compromise that exposes all report plaintext.

## Per-report encryption

Each report receives an independent high-entropy DEK.

The DEK protects:

- report text;
- original accepted PDF/image bytes.

A compromise of one report DEK must not decrypt another report.

## Key separation

The report database and attachment storage hold ciphertext.

The service/system able to unwrap or otherwise make report DEKs usable must be separated from ordinary application/database storage.

The Application Administrator and Infrastructure / Key Custodian are distinct roles. Normal administration of Django, PostgreSQL, blob storage, or Key Service infrastructure must not, by itself, provide report plaintext or arbitrary DEK unwrap capability.

The Reporter Gateway may create a report and initiate its encryption/storage pipeline but has no general capability to decrypt existing reports or unwrap arbitrary Report-DEKs. Key Service authorization is role-scoped, operation-scoped, report-scoped where applicable, state-aware, and server-authoritative.

## Existing SEALED reports vs compromised application server

The baseline accepts that an already-compromised reporter application can see future plaintext submissions passing through it.

The architecture should nevertheless avoid keeping all active report-unlocking authority permanently available to that process.

## Report-DEK replication and backup policy

Active Report-DEKs may be replicated live only inside the approved Key Service trust domain.

Per-report DEKs must not be included in historical backups or snapshots capable of later restoration. This prohibition includes wrapped/encrypted/derived representations whenever they can be combined with retained infrastructure keys or other backup data to restore the per-object key. Destruction must propagate to every supported live replica and must survive restore, rollback, delayed replication, stale replicas, and disaster recovery.

The project explicitly accepts that catastrophic loss of the complete DEK trust domain can irreversibly lose active reports. This is the approved `confidentiality > availability` trade-off.

No Key Service product is approved until a release-blocking proof of concept demonstrates these properties under every supported restore procedure.

## Cryptographic erase and finalization

Finalization is a resumable multi-service protocol, not one distributed atomic transaction. When a report is finalized:

1. preconditions, CAPTCHA, action-bound step-up, and durable audit receipt are verified;
2. Response Note persistence/protection is durably verified while remaining reporter-invisible;
3. the Report-DEK is irreversibly destroyed across every supported replica;
4. destruction is durably confirmed and audited;
5. only then may the Response Note become available;
6. all active leases are invalidated;
7. ciphertext deletion is initiated and failures are retried/alerted.

Destroyed report keys MUST NOT be resurrectable through backup restoration.

## Backup tension

General security best practice favors secure key backup for availability.

This project additionally requires irreversible report destruction.

Therefore the design must distinguish:

### Infrastructure keys

Examples:

- TLS keys;
- audit-signing keys;
- service-authentication keys;
- emergency-export organization key;
- key-service infrastructure keys as appropriate.

These may require secure, tested backup according to their own lifecycle.

### Per-report keys

A backup/recovery strategy must never permit a destroyed Report-DEK or Response-DEK to reappear. Live replication of active DEKs is permitted; restorable historical per-object key backups are forbidden.

The policy is approved. The final Key Service product, topology, and operational procedure remain OPEN CRITICAL until the required proof of concept succeeds.

## Candidate implementation

Python application cryptography candidate:

- libsodium via a maintained Python binding such as PyNaCl, subject to design validation.

Key-service candidate:

- OpenBao or another isolated vault/HSM-capable design.

No key-management product is approved until its snapshot/backup/replication/deletion semantics are proven compatible with non-resurrection.

## Response-DEK

Every Response Note has an independent Response-DEK. Ticket ID and Recovery Secret authorize the system to make that key usable; the Recovery Secret alone must not permanently decrypt an old ciphertext backup.

At the first valid read, server time sets `first_read_at` and Response-DEK expiry at 72 hours later. At expiry, the Response-DEK is destroyed across all supported replicas, recovery state/verifier is invalidated, residual ciphertext becomes unusable, and physical deletion proceeds separately with retry.

After server-authoritative expiry, the Key Service and recovery path refuse every use even if replica cleanup or physical deletion is temporarily retrying.

The exact AEAD, nonce strategy, AAD, key derivation/separation, verifier, wrapping construction, and Response-DEK representation remain OPEN CRITICAL and must not be invented in implementation.

## Sensitive memory

Where feasible:

- minimize plaintext lifetime;
- avoid unnecessary copies;
- zero/overwrite sensitive buffers when supported;
- do not assume Python memory can provide perfect deterministic zeroization.

The design must not claim stronger guarantees than the runtime can provide.
