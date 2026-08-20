# Architecture Decision Record

## Decision

Prefer small, explainable components and deterministic regression tests before
adding complex models or external integrations.

## Rationale

Explainability, reproducibility, and safe failure are more valuable for the
starter security tool than an opaque score that cannot be audited.
