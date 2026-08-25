# Anonymous Reporting — Security-First Handoff

This package transfers the current project knowledge into a form suitable for Codex and future developers.

The project is **not** a chat platform and **not** an authenticated whistleblowing portal. It is a minimal anonymous disclosure and one-response system designed around strong confidentiality and controlled operator access.

## Core flow

1. A reporter submits:
   - one text field;
   - optionally one PDF and/or up to three images.
2. The submission is stored encrypted.
3. An operator claims the report before seeing any content.
4. The operator processes the report in a tightly controlled session.
5. The operator publishes exactly one plain-text Response Note.
6. The original report encryption key is destroyed.
7. Report text and attachments become irrecoverable.
8. The reporter later retrieves only the Response Note using high-entropy recovery credentials.

## Security principle

The system is designed so that highly sensitive content is retained for the minimum necessary period and access is exceptional, attributable, and auditable.

The project owner explicitly prioritizes security over availability, convenience, and visual design.

## Start here

Read, in order:

1. `AGENTS.md`
2. `docs/00_PROJECT_SCOPE.md`
3. `docs/01_SECURITY_BASELINE.md`
4. `docs/02_THREAT_MODEL.md`
5. `docs/03_DATA_LIFECYCLE.md`
6. `docs/12_OPEN_SECURITY_DECISIONS.md`
7. `docs/19_SECURITY_SERVICE_INTERFACES.md`
8. `START-CODEX.md`

## Source material

`source/Questionario_requisiti_sicurezza_segnalazioni_anonime_v0.1.pdf` is the completed original questionnaire.

The Markdown specification incorporates later clarifications and therefore takes precedence where the source questionnaire differs.

## Current implementation status

The repository contains only an empty Django 5.2.17 development scaffold with no installed application, product route, or business logic.

Security-sensitive components remain blocked by their applicable OPEN decisions. The service interfaces and negative capability boundaries are approved as the implementation boundary, without closing those decisions.
