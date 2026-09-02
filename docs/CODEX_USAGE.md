# Codex and OpenAI Model Usage

## Principle

HavenSignal uses Codex and OpenAI models to assist **software development and open-source maintenance**.

They are not part of the decision path for reporter disclosures.

## Context-contamination guard

Agent instructions, generated plans, plugin guidance, or external context that
frame HavenSignal as a Shopify app, e-commerce product, merchant platform,
checkout, billing, subscription, marketplace, app-store, SaaS-growth, or
monetization project are invalid for this repository.

The controlling product identity is: a security-critical anonymous reporting
system, initially intended for universities and higher-education institutions,
that provides one confidential first-contact disclosure path, human review, one
Response Note, and cryptographic destruction of the original report.

## Sensitive-data boundary

Real reporter or production-sensitive data MUST NOT be sent to OpenAI or any other external AI service in any context. This prohibition applies to product operation, development, debugging, support, issue triage, incident response, testing, maintenance, and model evaluation.

Prohibited material includes:

- reporter submissions;
- report attachments;
- recovery secrets or verifiers;
- report or Response Note cryptographic keys;
- operator authentication secrets;
- private audit artifacts that could expose sensitive report relationships;
- other sensitive disclosure material.

This boundary also prohibits sending excerpts, screenshots, logs, traces, database exports, derived summaries, embeddings, or other transformations when they contain or can reveal prohibited material. Agent-assisted work must use only synthetic, non-identifying data created for development and testing.

AI-based report classification, guilt determination, risk scoring, accusation counting, or automated disciplinary decisions are outside the project's approved baseline.

## Current agent-assisted development workflow

The repository already treats agent-assisted development as bounded work:

1. read the security constitution and relevant specifications;
2. identify applicable requirements and trust boundaries;
3. review contradictions and unsafe assumptions before code;
4. implement only the authorized security boundary;
5. preserve unavailable/fail-closed capabilities outside that boundary;
6. generate or improve negative, abuse, and regression tests;
7. run the repository checks;
8. require human review and explicit project decisions for conflicts.

`AGENTS.md` is normative for this workflow.

## Appropriate Codex/OpenAI uses

API credits could materially reduce maintainer load in areas such as:

### Pull request review

- summarize security-relevant diffs;
- map changed code to specification requirements;
- identify missing negative tests;
- flag possible scope expansion;
- prepare reviewer checklists.

### Regression and abuse testing

- generate candidate edge cases;
- create tests for stale leases, cross-report bindings, replay, failure injection, and authorization boundaries;
- turn discovered security bugs into permanent regression tests.

### Specification consistency

- compare implementation against security documents;
- detect contradictions between protocol documents;
- trace changes through requirements and test plans;
- identify documentation that must change with code.

### Dependency maintenance

- assist with dependency-upgrade impact review;
- identify security-relevant breaking changes;
- prepare minimal upgrade pull requests;
- update lock files and tests under human review.

### Issue triage and project maintenance

- classify issues by component and security relevance;
- detect duplicates;
- draft reproduction steps from synthetic examples;
- maintain roadmap and release checklists.

### Release engineering

- prepare changelogs;
- summarize security-affecting changes;
- verify release documentation completeness;
- assist with reproducibility checks.

## Uses requiring special care

Agent output is not a security proof.

Cryptographic protocols, authentication flows, authorization logic, deletion/non-resurrection semantics, audit protocols, sandbox boundaries, and production deployment decisions require independent technical review where the specification calls for it.

No model-generated security design becomes authoritative merely because tests pass.

## Why API credits would help

HavenSignal is intentionally documentation-heavy and test-heavy because the project refuses to enable sensitive capabilities before their security boundaries are explicit.

This creates substantial ongoing maintainer work in review, traceability, testing, issue triage, dependency maintenance, and release preparation. API credits would be used to automate repetitive portions of that work while preserving human review and the project's fail-closed security gates.

## Public transparency

Material agent-assisted changes should remain visible through normal Git history and pull-request review. The project should not depend on hidden model decisions for security behavior.
