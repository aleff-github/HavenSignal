# First instructions for Codex

Open this repository as a local project in Codex.

## First prompt

Use this prompt before writing code:

> Read `AGENTS.md` and every Markdown document under `/docs`. Treat this as a security-critical anonymous reporting system that may contain extremely sensitive disclosures. Do not write code yet.
>
> Perform a consistency and implementability review of the specification. Identify:
> - contradictions;
> - requirements that cannot all be guaranteed simultaneously;
> - assumptions that need to be made explicit;
> - places where the proposed technology might violate a security property;
> - trust-boundary problems;
> - unsafe fallback behavior;
> - failure modes that could expose report content or permit audit-log tampering.
>
> Do not propose new product features, UI enhancements, chat, analytics, report aggregation, AI features, or authentication for reporters.
>
> For each issue, cite the exact document and requirement ID. Classify it CRITICAL, HIGH, MEDIUM, or LOW. Prefer confidentiality and audit integrity over availability and convenience.
>
> At the end, produce a short list of blocking decisions that must be resolved before implementation. Do not modify files unless explicitly asked.

## After the review is approved

Suggested second prompt:

> Based only on the approved specification, propose the minimal Django repository architecture and trust-boundary decomposition. Do not implement business logic yet. Show which processes/services should be separate, which databases/stores they may access, and which cryptographic capabilities each process must and must not possess. Explicitly map every component to requirements in `docs/01_SECURITY_BASELINE.md`.

## Only after architecture approval

Suggested third prompt:

> Create the minimal Django 5.2 LTS project scaffold, development configuration, dependency lock strategy, test structure, and security lint/test baseline. Do not implement report decryption, key management, emergency export, or file CDR yet. Keep all security-sensitive components behind explicit interfaces with failing placeholders until their design documents are approved.

## Important

Never ask Codex to "build the whole app" in one step.

Implement one security boundary at a time and require tests before moving to the next.

The current repository has progressed beyond these initial prompts. Before any
new implementation, read `docs/34_PRE_CODE_SECURITY_GATE.md`: its explicit
project-owner decision is required before the metadata-only Stage A may begin,
and it does not waive any external or production gate.
