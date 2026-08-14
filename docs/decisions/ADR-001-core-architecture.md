# ADR-001 — Verified Engagement Architecture

## Status

Accepted

## Decision

FarMartPulse will use a verification-first engagement architecture.

The canonical flow is:

Official FarMart Post
→ Engagement Discovery
→ Employee Matching
→ Verification
→ Canonical Engagement
→ Scoring
→ Leaderboard
→ Analytics

Engagement discovery may originate from:

- Platform API
- Manual Verification
- Import
- System

The discovery source does not determine the score.

Only verified canonical engagements may be scored.

## Core Rules

1. One real-world engagement produces at most one canonical engagement.
2. One canonical engagement produces at most one scoring event.
3. API and Manual Verification use the same scoring engine.
4. Points are derived from scoring rules, never supplied directly by the client.
5. Manual-first / API-later activity must reconcile into the same engagement.
6. Verification provenance must be preserved.
7. Score-affecting changes must be auditable.
8. Platform-specific APIs must not define the core engagement model.

## Consequences

LinkedIn and Instagram integrations plug into the engagement architecture rather than controlling it.

Manual Verification is a V1 reliability capability, not a separate scoring system.
