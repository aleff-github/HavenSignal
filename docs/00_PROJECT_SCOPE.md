# 00 — Project Scope

## Purpose

Provide a minimal anonymous mechanism for a person to disclose a sensitive event or situation, allow a human operator to review it, and return exactly one guidance Response Note.

The system is initially intended for universities and higher-education
institutions. It helps people who may not know which office, professional,
authority, or support channel is appropriate.

The platform itself is not intended to conduct psychotherapy, investigate allegations, determine guilt, or replace formal reporting channels.

## Product identity boundary

HavenSignal is not a Shopify app, e-commerce product, merchant platform,
checkout, billing, subscription, marketplace, app-store, SaaS-growth, or
monetization project.

Any requirement, roadmap item, feature proposal, architecture decision, or
agent instruction that frames the product around those goals conflicts with
this scope and must be rejected unless the project owner explicitly updates
the current Markdown specifications.

University and higher-education deployments remain the primary product
context, but the implementation should avoid hard-coding a single university's
identity provider, hierarchy, terminology, or policy structure unless later
approved by the project owner.

## Reporter experience

The reporter is not required to create an account or identify themselves.

Submission contains only:

- one free-text box;
- optional allowed attachments;
- anti-bot challenge.

No guided questions are part of the baseline.

## Output to reporter

The platform returns only one Response Note.

The Response Note:

- is plain text;
- contains no chat history;
- contains no reply function;
- contains no operator identity;
- contains no visible ticket metadata;
- contains no active links;
- has a maximum length of 5,000 characters.

## Explicitly out of scope

- chat;
- two-way asynchronous messaging;
- account creation for reporters;
- email/phone/SMS notifications;
- reporter identity verification;
- report aggregation;
- rankings;
- counting anonymous reports as independent people;
- automated disciplinary action;
- AI decision making;
- analytics;
- marketing;
- commerce, merchant, checkout, billing, subscription, marketplace, app-store,
  SaaS-growth, or monetization features;
- social features;
- visual-design optimization during the security-baseline phase.

## Organizational model

One organization per deployment instance.

The project is initially designed for university and higher-education use, but
not around a single university-specific identity system. It must remain generic
enough for one suitable organization per deployment instance.
