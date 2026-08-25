# 02 — Threat Model

## Primary assets

1. Report text.
2. Original accepted attachment bytes.
3. Per-report encryption keys.
4. Recovery credentials.
5. Response Note.
6. Operator credentials and session material.
7. Audit trail integrity.
8. Organization emergency-export private key material.
9. Key-service master/wrapping keys.
10. Security configuration.

## Highest-priority asset class

Report text and attachments are the highest-priority confidentiality assets.

## Adversaries in scope

### External attacker

May:

- attack public reporter and operator interfaces;
- attempt authentication bypass;
- send malicious files;
- attempt DoS;
- enumerate public identifiers;
- guess recovery credentials;
- exploit web, parser, dependency, or configuration vulnerabilities.

### Database administrator / stolen DB

Assume an adversary can obtain a complete copy of the application database.

Desired property: database contents alone do not reveal report plaintext.

### Attachment-storage theft

Assume an adversary can copy storage containing attachment ciphertext.

Desired property: storage alone does not reveal attachment plaintext.

### Application Administrator

The Application Administrator manages operators, application configuration, authorized audit access, anomalies, and alerts.

That role MUST NOT provide report reading, DEK access, direct unwrap/decrypt, operator impersonation, or a path to replace an operator's credentials with credentials controlled by the administrator.

### Infrastructure / Key Custodian

The Infrastructure / Key Custodian operates Key Service infrastructure, availability, replication, and infrastructure-key lifecycle.

That role does not automatically confer Operator, Application Administrator, audit-reader, or report-reader privileges. Normal infrastructure administration alone must not provide arbitrary report-decryption capability.

### Complete infrastructure compromise

If one adversary simultaneously controls:

- application and Operator Console code/deployment;
- operator credentials;
- Key Service control and credentials;

then the system is under complete infrastructure compromise. The baseline does not promise absolute report confidentiality against simultaneous control of all these trust domains.

This limitation does not weaken the requirement that any one normal administrative role, acting alone within its approved authority, lacks ordinary report-reading capability.

### Curious or malicious operator

An authorized operator may attempt:

- unnecessary repeated access;
- unauthorized copying;
- concurrent access;
- download;
- printing;
- copy/paste;
- unjustified reopening;
- emergency export for exfiltration.

The platform must reduce opportunity, make exceptional actions attributable, and prevent silent repeated access.

#### Accepted residual risk — Emergency Export

An authorized operator holding a legitimate current OPEN lease can deliberately invoke Emergency Export and create the authorized persistent encrypted copy.

CAPTCHA, action-bound MFA, audit receipts, signed/encrypted artifacts, and administrator alerts make the action attributable and detectable. They do not mathematically prevent an authorized operator from deliberately choosing the export path.

### Compromised application server

A complete active compromise of the reporter-facing application can expose future submissions that pass through the compromised process.

This limitation is explicitly accepted for the baseline.

The architecture MUST prevent Reporter Gateway compromise, by itself, from conferring a general ability to unlock all previously SEALED reports.

The Reporter Gateway has no general `decrypt_report(report_id)` or `unwrap_any_DEK(report_id)` capability. Its Key Service authority is limited by role, operation, report where applicable, and server-authoritative report state.

Priority during such compromise:

- prevent or reveal audit-history tampering;
- prevent access to key material not required by the compromised process;
- limit blast radius.

### Compromised operator workstation

The supported security profile assumes a dedicated, hardened operator workstation.

A fully compromised endpoint that can read screen/memory is outside the guarantee of the web application.

The software may technically run on ordinary work computers, but equivalent security guarantees are not promised.

### Compromised reporter device

Out of scope for platform guarantees.

Malware/keyloggers on the reporter device may steal report content or recovery credentials before/after transport encryption.

The platform should document this limitation clearly.

## Security goals under failure

Confidentiality takes precedence over availability.

If a key service, audit service, authentication dependency, or other mandatory security control required for an operation is unavailable, the sensitive operation should fail closed rather than degrade to a weaker mode.

## Explicit non-goals

The system cannot prevent an authorized operator from photographing a screen with an external camera.

UI restrictions against printing, copying, or downloading are defense-in-depth against accidental or casual extraction, not a mathematical guarantee against a malicious human with physical access.
