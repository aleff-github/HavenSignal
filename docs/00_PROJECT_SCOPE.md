# 00 — Project Scope

## Purpose

Provide universities and higher-education institutions with a minimal anonymous
mechanism for a person to disclose a sensitive event or situation, allow a
human operator to review it, and return exactly one guidance Response Note.

The system is intended to help people who may not know which office, professional, authority, or support channel is appropriate.

The platform itself is not intended to conduct psychotherapy, investigate allegations, determine guilt, or replace formal reporting channels.

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
- social features;
- visual-design optimization during the security-baseline phase.

## Organizational model

One university, higher-education institution, or other approved organization
per deployment instance.

Universities and higher-education institutions are the initial deployment
context. The implementation must not hard-code a particular institution's
identity provider, hierarchy, terminology, or internal policy so that each
approved deployment can be configured without weakening the common security
model.
