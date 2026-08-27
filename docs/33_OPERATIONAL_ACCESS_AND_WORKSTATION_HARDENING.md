# 33 — Operational Access and Workstation Hardening

## Status

**OWNER-APPROVED DESIGN (2026-08-26) — independent endpoint, authentication,
network, and operations review remains required. No production Operator,
Application Administrator, or Infrastructure / Key Custodian access is
authorized.**

This proposal defines the supported workstation builds, browser and local-data
controls, network access, session policy, Emergency Export transfer boundary,
administrator access, Key Custodian staffing and ceremonies, break-glass
behavior, patching, and failure handling. It does not approve hardware models,
an identity/VPN/bastion product, exact OS/browser package hashes, HSM/Key Service,
enterprise CA, organization staffing, physical facility, or deployment.

## Governing requirements

- `SEC-CONF-006..008`;
- `SEC-LOG-003..005`, `SEC-LOG-009..012`;
- `SEC-ACCESS-001..015`;
- `SEC-AUTH-001..009`;
- `SEC-KEY-001..007`;
- `SEC-ROLE-001..004`;
- `SEC-FINALIZE-001..006`;
- `SEC-EXPORT-001..006`;
- `SEC-ALERT-001..003`;
- `SEC-BROWSER-001..002`.

The threat model in `docs/02`, session model in `docs/06`, audit protocol in
`docs/23`, MFA proposal in `docs/25`, Key Service plan in `docs/27`, Emergency
Export proposal in `docs/28`, alert proposal in `docs/31`, and deletion
proposal in `docs/32` remain authoritative. A conflict stops implementation and
returns the decision to the project owner.

## Security outcome and guarantee boundary

The supported profile provides:

1. a dedicated physical workstation for each operational trust role;
2. current supported OS/browser security updates and measured configuration;
3. full-disk encryption, Secure Boot, least privilege, and no persistent
   browser profile containing report data;
4. no ordinary clipboard, printing, screenshot, cloud-sync, removable-storage,
   extension, or download path for report content;
5. network allowlisting and non-exportable device identity in addition to user
   password/WebAuthn;
6. strict separation of Operator, Application Administrator, and
   Infrastructure / Key Custodian devices, origins, credentials, and networks;
7. short, server-authoritative sessions and operation-bound step-up;
8. multi-person Key Custodian control with no report-selection or per-object
   DEK restore capability.

A fully compromised workstation that can read screen, process memory, keyboard,
or hardware display output remains outside the web application's guarantee.
The profile reduces likelihood and exposure; it cannot prevent a malicious
operator from photographing the screen, memorizing content, or using external
recording hardware. Production claims must state this boundary.

## Three non-interchangeable workstation classes

| Class | Permitted surface | Explicitly prohibited surface |
|---|---|---|
| Operator workstation | Operator Console and approved encrypted-export transfer broker | Administrator Console, Key Service management, email, general browsing, report originals as files |
| Application Administrator workstation | Administrator Console, alert inbox, authorized audit read | Operator Console, report/recovery surfaces, Key Service management, export recipient private key |
| Key Custodian workstation | Isolated bastion and infrastructure-control interfaces | Operator/Admin/Reporter/Recovery consoles, report selection/read, ordinary Internet browsing |

One physical device must not switch between these classes through accounts,
virtual machines, containers, browser profiles, dual boot, or temporary policy.
An individual must not hold more than one production trust role. Test/staging
access uses separate identities, devices, origins, keys, and data.

## Common hardware and operating-system baseline

Version 1 selects **Ubuntu Desktop 26.04 LTS**, latest supported security update
validated by the project at image-build time. A specific signed installation
image, package repository snapshot, kernel, firmware set, and hardware bill of
materials are pinned in deployment evidence; the document does not freeze an
obsolete patch version.

Required hardware:

- organization-owned x86-64 system with supported UEFI Secure Boot;
- TPM 2.0 for device identity/attestation and an enabled IOMMU;
- vendor-supported firmware with signed update path;
- at least 16 GiB RAM so swap can remain disabled;
- internal SSD/NVMe only; no secondary unencrypted internal disk;
- two organization-approved hardware WebAuthn/FIDO2 keys per person under
  `docs/25`.

Required build controls:

- Secure Boot and kernel lockdown enabled; unsigned boot/kernel modules denied;
- firmware/boot-order changes protected and external boot disabled after image
  installation;
- password-based LUKS2 full-disk encryption with Argon2 and no automatic TPM
  unlock; TPM-backed automatic FDE remains outside the profile until its exact
  implementation passes independent review;
- one unique high-entropy disk-unlock passphrase issued under the organizational
  credential procedure; no shared passphrase, escrowed convenience slot,
  plaintext keyfile, unattended unlock, or on-device recovery copy;
- no hibernation, suspend-to-disk, crash dumps, kdump, swap partition/file, or
  unencrypted temporary filesystem;
- AppArmor enforcing, host firewall default deny, time synchronization to the
  approved internal source, and signed package verification;
- operator/admin/custodian user is an unprivileged standard account with no
  `sudo`, package installation, service control, kernel/module control, or
  policy-edit capability;
- a separately managed maintenance identity is disabled during normal use and
  cannot authenticate to application roles;
- remote desktop, inbound SSH, VNC, remote assistance, developer services,
  discovery protocols, local web servers, and peer-to-peer services absent;
- CUPS/printing stack, screenshot/recording utilities, clipboard manager,
  cloud-sync clients, consumer password managers, email/chat clients, office
  suites, general developer tools, and unapproved shells absent from the role
  account;
- USB mass storage, MTP/PTP, Thunderbolt/PCIe hot-plug, Bluetooth, camera, and
  microphone denied by firmware/OS policy except the narrowly approved export
  transfer ceremony;
- automatic screen lock after two minutes of inactivity; unlock requires the
  local account secret and forces application reauthentication before sensitive
  content is displayed again.

The LUKS header/passphrase is not backed up because role workstations are
reprovisionable and must not contain the authoritative report store. Loss of
the passphrase/device causes secure reimage and credential revocation, not a
disk-recovery exception.

## Pinned image, update, and drift policy

The golden image is built reproducibly from approved signed repositories,
contains no production user/service secret, and receives a signed inventory of
package hashes, firmware, browser policy, firewall policy, trusted roots, and
enabled services. A second authorized reviewer approves each production image.

Update deadlines from vendor publication or internal confirmation, whichever
is later:

- actively exploited or browser/security-critical update: deploy within 24
  hours after compatibility smoke test;
- other critical/high OS or firmware security update: deploy within 48 hours;
- medium/low security updates: next maintenance window, at most 30 days;
- rebuild from the current approved image at least every 90 days.

If a deadline cannot be met, the device is isolated and cannot access a
production surface until patched or an explicit project-owner security decision
approves a compensating control. There is no silent "continue vulnerable"
mode.

At boot and at least daily, self-hosted configuration measurement verifies the
signed inventory. Drift, Secure Boot failure, unexpected service/module/device,
missing update, policy change, or clock failure quarantines the workstation and
creates a controlled alert. Measurement sends only device ID, image/policy
version, closed result code, and server time—never browser history, screen,
clipboard, report IDs/content, or arbitrary command output.

Updates come through organization-controlled mirrors/proxies. A role
workstation has no general Internet package, browser, telemetry, crash-report,
extension, or time-service access.

## Operator browser profile

Version 1 selects **Firefox ESR 153**, always at the latest supported security
point release after validation. The enterprise policy bundle is versioned with
the workstation image and checked at startup.

Required behavior:

- one exact Operator Console HTTPS origin and no general navigation;
- only the private organization trust roots and exact production origin;
  certificate errors are not bypassable;
- block all extensions, add-ons, themes, profile import/export, browser sync,
  Firefox account, password saving, form/search history, session restore,
  telemetry, studies/experiments, recommendations, Pocket, AI/chatbot features,
  remote improvement/configuration, feedback/crash upload, and third-party
  services;
- block developer tools, `about:config`, alternate profiles, external protocol
  handlers, custom proxy changes, local-network access, WebRTC, geolocation,
  notifications, camera, microphone, serial, HID, MIDI, and unapproved USB;
- disable the built-in PDF viewer because ordinary attachment view is the
  approved PNG safe representation only;
- disable printing, print preview, save-page, screenshot, reader mode,
  translation, password reveal, drag/drop to filesystem, and ordinary browser
  downloads;
- no browser disk cache, persistent cookies beyond the session, service worker,
  offline storage, localStorage/IndexedDB use by the application, or saved
  credentials;
- run one ephemeral browser profile on bounded `tmpfs`; destroy it on logout,
  browser crash recovery, screen-lock reauthentication failure, and reboot;
- clear all session cookies, memory-backed cache, clipboard state, and temporary
  safe representations when the role session ends.

Policy names and availability are validated against the exact pinned Mozilla
enterprise policy templates. Unsupported behavior is enforced at the kiosk/
OS/network layer or the image is rejected; an ignored/unknown browser policy is
not accepted as protection.

## Clipboard, printing, capture, and local files

The locked Wayland kiosk session provides no clipboard bridge or clipboard
history for the Operator Console. The application exposes no copy button for
report text, safe attachment views, Recovery Secrets, or protected notes.
Keyboard paste into the Response Note is also disabled in the supported profile
to avoid importing uncontrolled clipboard data.

Printing and print-to-file are unavailable because CUPS, browser print UI, and
PDF virtual printers are absent. Screenshot/recording keybindings, desktop
portal, utilities, and remote-display APIs are unavailable. These controls do
not claim to stop an external camera or a malicious kernel/firmware/device.

Report text and safe attachment PNGs are rendered only in the browser inside a
current server-authoritative OPEN lease. They are never exposed as filesystem
paths, drag targets, browser downloads, desktop thumbnails, recent files, or
OS search/indexing input.

## Emergency Export transfer exception

Emergency Export remains the only approved download-like path. It transfers
only the final already-encrypted `age` artifact from `docs/28`; the workstation
never possesses the organization recipient private key and cannot decrypt it.

A dedicated privileged transfer broker, unavailable to ordinary browser
content, accepts only:

- the exact export MIME/profile and binary `age` header;
- one server-issued export job/delivery capability bound to current session,
  lease, artifact hash, length, expiry, and consumed state;
- a maximum 64 MiB encrypted object into a `noexec,nodev,nosuid` bounded `tmpfs`;
- one organization-inventoried removable destination unlocked/mounted by the
  broker only after a separate local export ceremony.

The broker verifies the received encrypted-artifact hash/length against the
audited job, writes it once to organization-controlled encrypted removable
media, syncs and verifies the copy, unmounts, consumes the delivery, and deletes
the `tmpfs` object. Disconnect, hash mismatch, unapproved media, timeout,
browser crash, or transfer uncertainty consumes/quarantines the attempt and
deletes local staging; a new export requires the complete authorization flow.

No email, cloud drive, network share, clipboard, ordinary filesystem, or
user-selected destination is permitted. The removable artifact leaves the
platform lifecycle and enters the separately approved organization custody
procedure. If the broker/profile is unavailable, export release fails closed.

## Operator network and login-session profile

The public Internet exposes only the organization VPN gateway—not the Operator
Console origin directly. A supported workstation requires:

1. device admission using a non-exportable TPM-backed device credential;
2. organization VPN to an Operator-only network segment;
3. TLS server validation and a separate non-exportable client device
   certificate at the Operator Console boundary;
4. user password plus the `docs/25` device-bound WebAuthn factor.

Host firewall and network policy allow only VPN bootstrap, approved internal
DNS/time/update/attestation endpoints, the exact Operator Console origin, and
the export transfer service. No inbound connection or east-west workstation
traffic is allowed.

The server-side Operator login session has:

- a random rotated session ID and distinct Operator cookie/origin;
- `Secure`, `HttpOnly`, host-only narrow path, approved `SameSite`, CSRF, and
  `no-store` controls;
- 15-minute idle expiry and eight-hour absolute expiry, both non-sliding beyond
  the absolute boundary;
- one active session per operator; a new login terminates the earlier session,
  challenges, step-ups, and report lease through a controlled interruption;
- immediate termination on account/factor/device disable, image-policy failure,
  network identity change, screen-lock reauthentication failure, or suspected
  compromise;
- no remember-me, session recovery link, browser persistence, or administrator
  session minting.

The stricter report lease remains five-minute idle/60-minute absolute under
`docs/06`; refreshing or extending the login session never extends a lease or
StepUpAuthorization.

## Application Administrator access profile

The Administrator Console has a distinct DNS name, RP/origin, cookie, TLS
client-certificate profile, VPN segment, device image, account store, and
WebAuthn credential set. It is not reachable from the Operator network or
ordinary Internet. Administrator credentials cannot authenticate to Operator,
Recovery, Reporter, Key Service, bastion, or export-decryption surfaces.

The administrator workstation uses the common Ubuntu/Firefox baseline with an
administrator-specific origin allowlist. It may display controlled alert/audit/
account/configuration metadata but cannot route to report ciphertext,
attachments, safe views, Response Notes, Recovery Secrets, DEK APIs, or
operator sessions. It has no Emergency Export transfer broker.

Administrator login requires password plus approved hardware WebAuthn under
`docs/25`. Sessions use one active session per administrator, ten-minute idle
expiry, four-hour absolute expiry, reauthentication after screen lock, and
immediate revocation on account/factor/device/configuration anomaly.

Actions requiring a fresh 120-second operation-bound step-up include:

- account creation, enablement, role/status change, and credential lifecycle;
- security, authentication, alert-routing, retention, trust-root, or deployment
  configuration change;
- audit evidence export or bulk view;
- workstation/image-policy approval;
- flood-deletion declaration under `docs/32`.

Emergency account disable and session revocation may occur immediately with
administrator step-up and durable audit; they do not require a second approver
because delay would preserve access. Enablement, credential enrollment/
replacement/recovery, trust/security configuration, retention shortening, and
flood deletion retain their separately required quorum/delay and cannot be
completed by one administrator.

There is no "login as operator", password disclosure/reset to an
administrator-known value, factor enrollment under administrator custody,
session/token generation, recovery bypass, report preview, database query
console, Django Admin fallback, or support impersonation endpoint.

Administrator source device ID, VPN identity, and controlled network address
may be recorded for accountability. Raw headers, browser data, free text,
secrets, and any reporter-controlled value remain prohibited.

## Administrative step-up profile without dummy report context

The exact `docs/25` version-1 StepUpAuthorization is report/lease-bound. An
administrator operation must not insert dummy report/lease IDs or weaken its
schema. This proposal defines the requirements for a separately reviewed
version-2 administrative authorization:

```text
AdministrativeStepUpAuthorization v2
  authorization_id: random 16-byte identifier
  administrator_id: internal 16-byte identifier
  session_id: internal 16-byte identifier
  device_id: internal 16-byte identifier
  operation: closed registry
  target_kind: closed registry
  target_id: internal 16-byte identifier or nil only by exact profile
  artifact_kind: closed registry
  artifact_binding: 32-byte keyed deterministic-CBOR binding
  binding_key_epoch: integer
  webauthn_credential_row_id: internal identifier
  issued_at: server time
  expires_at: issued_at + 120 seconds
  consumed_at: server time or null
  consumed_by_operation_id: internal identifier or null
```

It preserves the same fresh 32-byte WebAuthn challenge, exact RP/origin/UV/
attestation checks, opaque POST-only handle, server-side row, actor/session/
device/operation/target/artifact binding, single-use transaction, no bearer
authorization, no URL/log persistence, and fail-closed behavior as `docs/25`.
Each operation profile fixes exact descriptor bytes and required quorum. It
grants no report, lease, Operator, or Key Service capability.

This same profile family may bind the metadata-only flood batch from `docs/32`
for each required administrator/operator approval, with actor role fixed by the
specific profile. Cross-role, cross-operation, cross-batch, or dummy-context
reuse fails closed. Independent authentication/protocol review is mandatory.

### Inert Stage A v2 foundation record

`security_interfaces/administrative_step_up_descriptors.py` represents only the
structural v2 foundation that can be validated without inventing a missing
operation profile: exact 16-byte authorization, administrator, session, and
device identifiers; the approved binding purpose and unsigned key epoch; exact
120-second non-sliding timing; and an unused-only state.

The structurally valid result explicitly has no complete operation profile,
does not verify WebAuthn or artifact binding, and authorizes neither an
administrative action nor flood deletion. Operation, target kind/ID, artifact
kind/binding, credential-row ID, challenge, handle, persistence, consumption,
actor-role-specific flood approvals, workstation/session proof, and every
external or production gate remain absent and OPEN.

## Infrastructure / Key Custodian staffing and access

Production requires at least three individually named Key Custodians so two
can form quorum without a shared account. A custodian cannot simultaneously be
an Operator or Application Administrator. Each custodian has two approved
hardware keys and in-person credential lifecycle equivalent in strength to
`docs/25`, but uses separate infrastructure credentials/origins.

The custodian workstation uses the common hardened build without application
browser access. Network path is:

```text
Custodian workstation
  -> custodian-only VPN/device identity
  -> self-hosted hardened bastion
  -> isolated Key Service management network
```

No Key Service management endpoint has public ingress. Bastion access requires
a hardware-backed OpenSSH FIDO key with user verification and a self-hosted CA
certificate valid at most 15 minutes, limited to the named principal/host/
command class. Password, static SSH key, agent/X11/port forwarding, shared
account, direct root login, unrestricted shell, and long-lived certificate are
disabled.

One custodian may perform allowlisted read-only health and replication-status
checks that expose no per-report identifiers or key material. Any change to
Key Service policy/topology, quorum/replication, infrastructure key lifecycle,
HSM/seal/CA configuration, backup/restore, disaster recovery, privileged
break-glass, or production PoC evidence requires two distinct custodians and a
pre-authorized immutable change descriptor.

The Application Administrator or Operator may supply a separate approval where
another protocol explicitly requires cross-role quorum, but does not receive a
bastion credential or Key Service role. A custodian approval is similarly not
an administrator session.

## Key Custodian command and evidence model

The bastion exposes versioned command wrappers rather than a general production
shell. Wrappers fix target class, arguments, timeout, expected state, and output
schema. They never accept an application report ID for arbitrary read/decrypt,
export key bytes, enumerate per-report key handles, or invoke a supported
restore of destroyed per-object DEKs.

Controlled evidence records:

- ceremony/change ID;
- custodian internal IDs;
- authenticated workstation and certificate IDs;
- approved command code and configuration version;
- server timestamps, target service instance class, and closed outcome;
- resulting health/configuration digest where not content-derived.

It does not record raw terminal video, stdout/stderr, command line, environment,
secret/key bytes, seal shares, tokens, report/key handles, arbitrary notes, or
untrusted product errors. Product output is parsed through a closed schema; an
unknown response stops the operation and is not copied into logs.

Configuration is reviewed as secret-free version-controlled data and deployed
from an immutable signed artifact after quorum. Runtime secrets are injected
only inside their approved HSM/secret domain and never committed to Git,
automation prompts, tickets, shell history, environment dumps, or clipboard.

## Infrastructure keys, backups, and non-resurrection

Infrastructure TLS, CA, HSM/seal, service-authentication, audit-signing, and
export-signing/recipient key lifecycles are distinct and may use separately
approved encrypted backup under vendor/HSM dual-control.

Plaintext, wrapped, encrypted, derived, replicated, snapshot, log, or exportable
per-report Report-DEK/Response-DEK backup remains forbidden. No break-glass,
root, HSM recovery, disaster recovery, or vendor support procedure may restore
a destroyed per-object DEK. If a candidate product cannot enforce this, it
fails `docs/27` and is rejected.

Infrastructure backup/restore ceremonies require two custodians, offline
inventory, controlled audit, quarterly canary restore, and proof that no
per-object key material is present. Production restore remains blocked until
the non-resurrection test passes against the exact restored topology.

## Break-glass procedure

Break-glass exists only for infrastructure availability/containment; it is not
a report-reading, key-export, deleted-key-restore, MFA-bypass, administrator-
impersonation, or operator-session mechanism.

Activation requires:

1. a declared CRITICAL infrastructure incident and closed reason code;
2. two distinct Key Custodians physically present or connected through the
   approved independent management path;
3. both hardware credentials and vendor/HSM-supported dual control—no custom
   secret splitting or single sealed master password;
4. a 15-minute non-renewable privileged capability bound to exact command class,
   target instances, incident ID, and expected state;
5. durable audit and administrator alert acceptance when those systems are
   available without weakening immediate containment;
6. automatic revocation at expiry, command completion, state mismatch, or one
   participant withdrawal.

If audit is unavailable for an operation that would disclose, destroy, export,
or change per-object key usability, that operation fails closed. A narrowly
defined action that only isolates a compromised node or revokes access may
proceed when delay would preserve attacker access; it must persist a closed
local evidence record and reconcile truthful audit/alert evidence as soon as
the boundary returns. It cannot make any DEK usable.

After use: rotate exposed infrastructure credentials, revoke all incident
certificates, independently compare configuration/state, run the full
non-resurrection canary, review audit/alert/bastion evidence, and obtain
project-owner security sign-off before normal service resumes.

## Credential lifecycle and periodic review

- Device certificates and workstation identities rotate at least every 90
  days and are revoked immediately on loss, role change, reimage, or anomaly.
- Short-lived SSH certificates expire in at most 15 minutes; their CA and
  hardware keys follow a separately approved HSM lifecycle.
- Operator/admin/custodian hardware-factor inventory is reconciled monthly.
- Accounts, roles, device inventory, network rules, bastion principals, command
  registry, and quorum assignments are reviewed quarterly by two distinct
  trust roles.
- Dormant accounts are disabled after 30 days without approved use; re-enable
  follows the full reviewed procedure, not login alone.
- Personnel departure disables accounts/devices/certificates/sessions
  immediately and rotates any shared infrastructure material they could use.
- A complete workstation, administrator recovery, custodian quorum, break-glass,
  infrastructure restore, and non-resurrection exercise runs at least annually
  and after material topology/product changes.

No procedure uses email/SMS reset, recovery code, shared password, cloud
identity fallback, vendor remote access, password-only emergency login, or
administrator-generated operator/custodian factor.

## Data, logging, and monitoring

Endpoint/network/security monitoring is self-hosted. It may collect only:

- internal device/account/service identifiers;
- signed image/policy/package/firmware versions;
- login/step-up/lock/quarantine event codes and controlled outcomes;
- administrator/custodian network identity and bounded timing;
- firewall/attestation result codes and unexpected service/device class.

It must not collect browser DOM, screen pixels, clipboard, keystrokes, report/
Response Note text, attachment data/metadata, original filename, Recovery
Secret, protected note, DEK/key bytes, session/challenge handle, raw URL/query/
header/body, arbitrary command output, or raw exception. No external telemetry,
cloud crash reporting, analytics, DLP content inspection, or third-party remote
support is enabled.

## Failure behavior

| Failure | Required result |
|---|---|
| Unsupported OS/browser/firmware or missed patch deadline | Quarantine device; no production access |
| Secure Boot/FDE/IOMMU/policy/attestation failure | Deny VPN/application/bastion admission |
| Unknown/ignored browser policy | Reject image; no assumed protection |
| Ephemeral-profile/tmpfs cleanup uncertainty | Terminate role session, reboot/reimage before reuse |
| Clipboard/print/capture/download control unavailable | No report rendering on that device |
| Export transfer broker/media/hash failure | No release completion; consume/quarantine and clean staging |
| Device certificate/VPN unavailable | No direct Internet fallback |
| Login MFA/session/step-up dependency unavailable | Deny login/protected action |
| Administrator second-role approval unavailable | Keep change pending/disabled; no bypass |
| Custodian quorum unavailable | No sensitive infrastructure change or recovery |
| Bastion/CA/command-wrapper uncertainty | Deny access; no general shell/static-key fallback |
| Break-glass audit unavailable | Only exact access-revocation/node-isolation containment may proceed; no DEK use/change |
| Restore/non-resurrection evidence incomplete | Keep topology out of production |
| Monitoring failure | Preserve confidentiality controls, quarantine affected admission path, alert through independent boundary |

## Required tests before enablement

Release-blocking acceptance must prove:

- exact signed Ubuntu image/package/firmware inventory, Secure Boot, LUKS2,
  disabled swap/hibernate/dumps, AppArmor, least privilege, firewall, and IOMMU;
- role accounts cannot gain local administration, install software, enable
  services, boot externally, attach storage, or access another role's network;
- Firefox ESR enterprise policies are recognized/enforced and alternate
  profile, extension, telemetry, sync, history, cache, developer, PDF, print,
  clipboard, capture, drag/drop, protocol, and ordinary download paths fail;
- ephemeral profile/safe-view/session artifacts disappear after normal logout,
  crash, lock failure, power loss, and reboot, with no swap/core/thumbnail/index;
- Operator/Admin/Custodian device credentials, VPN segments, TLS certificates,
  RP/origins, cookies, WebAuthn credentials, accounts, and routes reject every
  cross-role use;
- session idle/absolute expiry, one-session rule, lock reauthentication,
  revocation, stale cookie/tab, and device-policy loss terminate access server
  side without extending ReportLease or StepUpAuthorization;
- administrative version-2 step-up is single-use, 120 seconds, exact-descriptor
  bound, and rejects cross-admin/device/session/operation/target/batch replay;
- administrator functions cannot create operator sessions, control operator
  factors, query report content, reach Key Service, or bypass quorum/delay;
- export broker accepts only the exact encrypted artifact/capability/hash/size/
  media, has no private decrypt key, and cleans every failure boundary;
- at least three custodian identities, two-person ceremonies, 15-minute FIDO
  SSH certificates, principal/host/command restrictions, no forwarding/root/
  static key/general shell, and revocation work across races and crashes;
- every break-glass path cannot read/select reports, export key bytes, restore
  a destroyed DEK, bypass audit for DEK use, or remain active after 15 minutes;
- quarterly infrastructure restore and `docs/27` destructive tests prove no
  per-object key backup/resurrection;
- prohibited-data sentinels are absent from endpoint monitoring, VPN, browser,
  bastion, audit, alerts, logs, metrics, traces, crash output, and update systems.

A policy document, browser screenshot, VM-only simulation, manual checklist,
mock hardware key, or one-person happy-path demo is insufficient. Acceptance
requires the exact physical hardware, firmware, signed image, browser, FIDO
keys, VPN/device identity, bastion, network policy, and production-equivalent
service boundaries.

## Consolidated decisions approved at the pre-code gate

The final pre-code owner review must decide:

1. three physically separate workstation classes with no role mixing;
2. Ubuntu Desktop 26.04 LTS, latest validated patches, Secure Boot, passphrase
   LUKS2, no swap/hibernate/dumps, no local admin, and signed drift-controlled
   90-day rebuilds;
3. Firefox ESR 153 latest patch, one-origin ephemeral kiosk profile, no
   extensions/telemetry/sync/persistence/PDF/print/clipboard/capture/ordinary
   downloads;
4. Operator VPN + device identity + client certificate + password/WebAuthn,
   15-minute/eight-hour login session, and existing stricter ReportLease;
5. separate Administrator origin/network/device with ten-minute/four-hour
   session, no impersonation/report access, and the version-2 administrative
   exact-artifact step-up profile;
6. the encrypted-only 64 MiB Emergency Export transfer broker and inventoried
   removable-media ceremony;
7. at least three Key Custodians, two-person sensitive ceremonies, isolated
   bastion, hardware-backed 15-minute OpenSSH certificates, command wrappers,
   and no application/per-object-key authority;
8. the stated break-glass, infrastructure backup/restore, credential rotation,
   patching, monitoring, periodic review, and failure-closed policies.

Independent endpoint/authentication/network/operations review, exact hardware
procurement, OS/browser artifact pinning, VPN/device-identity/bastion/CA
selection, FIDO validation, kiosk/transfer-broker implementation, physical
facility/media procedure, staffing, Key Service/HSM product, destructive PoC,
and production acceptance remain release gates after owner approval.

## External design references

- [Ubuntu 26.04 LTS release notes](https://documentation.ubuntu.com/release-notes/26.04/)
- [Ubuntu release and support cycle](https://ubuntu.com/about/release-cycle)
- [Ubuntu full-disk encryption](https://documentation.ubuntu.com/security/security-features/storage/encryption-full-disk/)
- [cryptsetup/LUKS project documentation](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/FAQ.md)
- [Firefox ESR release cycle](https://support.mozilla.org/en-US/kb/firefox-esr-release-cycle)
- [Firefox Enterprise policy reference](https://firefox-admin-docs.mozilla.org/reference/policies/)
- [Firefox Enterprise 153 release notes](https://support.mozilla.org/en-US/kb/firefox-enterprise-153-release-notes)
- [OpenSSH `ssh-keygen` certificates and FIDO authenticators](https://man.openbsd.org/ssh-keygen)
- [OpenSSH `sshd_config` access restrictions](https://man.openbsd.org/sshd_config)
