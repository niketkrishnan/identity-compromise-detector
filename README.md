# ML-Based Identity Compromise and Account-Takeover Detection

A defensive identity-risk analytics project that combines transparent behavioral signals with an Isolation Forest model. It highlights new devices, new network ASNs, new countries, unusual hours, failed authentication, and privileged access, then produces an analyst-facing explanation.

> **Authorized-use notice:** The fixture uses synthetic identifiers and the project recommends actions only. It does not lock accounts, revoke tokens, or access identity providers.

## Run locally

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python evaluate.py
pytest
```

## Privacy and fairness

The starter fixture contains no personal information. A production-quality evaluation must document the dataset license, minimize identifiers, compare user-level and population-level baselines, report false positives by relevant cohort, and discuss VPNs, travel, shared devices, mobile networks, and sparse histories.

## Evaluation roadmap

The next milestone is to evaluate on a verified public authentication dataset such as the LANL authentication dataset or another licensed academic benchmark. If an approved dataset cannot be obtained, the project must remain explicit about fixture-only results and must not claim production performance.
