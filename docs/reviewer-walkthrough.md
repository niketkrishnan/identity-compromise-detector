# Reviewer walkthrough

Run `python evaluate.py` and inspect `artifacts/identity_results.json`.

The eight-event synthetic fixture produces three medium-or-higher alerts. One `u-bob` sequence reaches score `0.62` because failed authentication, a new device, a new ASN, a new country, unusual hours, and privileged identity appear together. The report is pseudonymous and recommendation-only.

The example demonstrates explainability and privacy boundaries, not production account-takeover accuracy.
