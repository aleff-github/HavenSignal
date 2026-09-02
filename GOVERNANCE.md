# Governance

## Current model

HavenSignal is currently a small, maintainer-led open-source project in a security-first pre-alpha stage.

During this bootstrap phase, the project maintainer is responsible for:

- scope and product decisions;
- accepting or rejecting specification changes;
- recording project-owner decisions and enforcing the documented status of security gates;
- pull request review;
- issue triage;
- releases;
- coordinating independent review when a design requires it.

This structure is intentionally simple while the contributor base is small. It is not intended to permanently centralize all project authority.

## Decision principles

Decisions are made in this order of priority:

1. confidentiality of report text and attachments;
2. integrity and tamper-evidence of the audit trail;
3. reporter anonymity and metadata minimization;
4. operator authentication, accountability, and least privilege;
5. correct cryptographic deletion and non-resurrection;
6. availability;
7. maintainability;
8. user-interface convenience and visual design.

A security property must not be weakened merely to make implementation faster or easier.

## Specification authority

For implementation decisions, precedence is defined in `docs/SECURITY_CONSTITUTION.md`.

Security-sensitive behavior should be documented before it becomes an enabled product capability.

## Pull requests

Normal changes must enter `main` through pull requests and automated checks.

The `main` branch must:

- block force pushes;
- require CI status checks;
- require conversation resolution;
- use pull requests for changes.

When multiple active maintainers exist, the project should additionally require independent review for security-sensitive changes.

## Security decisions

Changes affecting authentication, authorization, cryptography, key lifecycle, report storage, file handling, audit integrity, recovery, deletion, export, networking, or production deployment require:

- identification of the applicable requirements;
- explicit trust-boundary analysis;
- documented failure behavior;
- negative and abuse tests;
- review against the relevant security protocol.

A merge does not by itself authorize production deployment.

The maintainer or project owner may close only the internal decision gates that the specifications explicitly place within that role's authority. Neither a maintainer decision nor a merge may substitute for, waive, or mark complete any required independent review, legal or operational approval, product selection, production-equivalent proof, service acceptance, staffing or custody requirement, or production deployment gate. The open gates recorded in `docs/34_PRE_CODE_SECURITY_GATE.md` remain blocking until their named evidence and authority are present.

## Becoming a maintainer

A contributor may be considered for maintainer responsibility after demonstrating sustained work such as:

- high-quality pull requests;
- constructive security review;
- issue triage;
- documentation stewardship;
- reliable release or testing work;
- respect for the project's narrow scope and fail-closed design.

Maintainer access is granted gradually and should follow least privilege.

## Future governance

If HavenSignal grows beyond a small maintainer group, this document should evolve to define:

- named maintainer roles;
- security-review quorum rules;
- release authority;
- conflict-resolution procedures;
- removal/inactivity procedures;
- responsible stewardship of project infrastructure.

Governance changes should remain public and reviewable.
