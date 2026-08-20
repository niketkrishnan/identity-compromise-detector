# Reviewer Guide

## Five-minute path

1. Run `python evaluate.py` and inspect the identity result artifact.
2. Trace feature construction, baseline learning, anomaly scoring, and reason generation.
3. Review tests for malformed events, privacy-safe identifiers, configurable thresholds, and report projections.
4. Discuss false positives, cohort fairness, concept drift, and why response remains recommendation-only.

## Evidence of engineering judgment

The project treats privacy and analyst trust as first-class constraints, not as a post-processing note.
