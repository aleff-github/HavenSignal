# Project Impact

## The problem HavenSignal targets

HavenSignal focuses on a narrow but important first-contact problem:

> A person may need help with a sensitive situation but may not know which office, professional, authority, or support service is appropriate, and making the first disclosure may itself feel risky.

Higher education is one motivating example because institutional hierarchies can create substantial power differentials. Research and guidance from the U.S. National Academies have documented that fear of retaliation, career consequences, unclear or convoluted processes, and power imbalances can discourage formal reporting and help-seeking in academic settings.

Relevant background:

- National Academies, *Sexual Harassment of Women: Climate, Culture, and Consequences in Academic Sciences, Engineering, and Medicine* (2018): https://doi.org/10.17226/24994
- National Academies, *Preventing Sexual Harassment and Reducing Harm by Addressing Abuses of Power in Higher Education Institutions* (2023): https://doi.org/10.17226/26631
- National Academies, *Identifying Gaps in Sexual Harassment Remediation Efforts in Higher Education* (2025): https://doi.org/10.17226/29095

These sources motivate the problem space; they do not validate HavenSignal itself or imply that HavenSignal is a substitute for institutional reform.

## What HavenSignal is trying to contribute

HavenSignal is designed as a minimal, privacy-preserving bridge between an uncertain first disclosure and appropriate human guidance.

The intended contribution is not automated judgment. It is a carefully constrained mechanism that allows:

- one anonymous disclosure;
- optional tightly controlled evidence attachments;
- human review;
- one plain-text guidance Response Note;
- minimization and eventual cryptographic destruction of the original sensitive material.

## Why minimalism matters

Many reporting systems naturally evolve toward accounts, case-management workflows, persistent conversations, analytics, and integrations.

Those features can be useful in other products, but they also increase:

- retained sensitive data;
- metadata;
- number of actors and services with access;
- long-lived identifiers;
- operational complexity;
- attack surface;
- opportunities for accidental misuse.

HavenSignal deliberately explores a different point in the design space: how little infrastructure and retained information are necessary to provide a useful first human response.

## Intended environments

The architecture is organization-agnostic. Potential environments may include:

- universities and research institutions;
- nonprofit organizations;
- professional associations;
- institutions that need a privacy-preserving first-contact channel;
- other organizations where a reporter may be uncertain about the correct support path.

Deployment suitability must be evaluated case by case. HavenSignal should not be represented as compliant with a jurisdiction, sector, or policy framework unless that has been independently established.

## What success would look like

A successful HavenSignal deployment would not be measured by the number of accusations collected.

More appropriate measures include:

- whether people can make the first disclosure without creating an identity account;
- whether a qualified human can provide useful routing/guidance;
- whether sensitive source material is retained only for the intended period;
- whether access and exceptional actions are attributable;
- whether deletion/non-resurrection properties hold under realistic failure scenarios;
- whether the system remains understandable and auditable by independent reviewers.

## What HavenSignal does not claim

HavenSignal does not claim to:

- save lives by itself;
- guarantee absolute anonymity;
- protect a reporter whose endpoint is fully compromised;
- prevent an authorized person from photographing a screen;
- investigate allegations;
- determine guilt;
- replace emergency services, law enforcement, legal advice, medical care, psychotherapy, safeguarding teams, unions, or formal reporting channels.

The project's value depends on careful deployment, qualified human operators, institutional procedures, independent security review, and honest communication about residual risk.
