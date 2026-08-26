# Codex and OpenAI Model Usage

## Principle

HavenSignal uses Codex and OpenAI models to assist **software development and open-source maintenance**.

They are not part of the decision path for reporter disclosures.

## Sensitive-data boundary

The HavenSignal product must not send the following to OpenAI APIs as part of normal reporting operation:

- reporter submissions;
- report attachments;
- recovery secrets or verifiers;
- report or Response Note cryptographic keys;
- operator authentication secrets;
- private audit artifacts that could expose sensitive report relationships;
- other sensitive disclosure material.

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
