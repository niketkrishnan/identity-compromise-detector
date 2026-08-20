# Evaluation Plan

The current demonstration uses local identity events with synthetic identifiers and a future licensed public-authentication benchmark and is intended to verify
behavior, not to claim production performance. Future benchmark results must
include dataset version, license, split strategy, baseline, metrics, and the
exact command used to reproduce them.

Evaluation should report detection quality, false positives, latency, and
explanation quality where applicable. Security controls should be compared
with a baseline configuration rather than presented without context.


## Publication hardening

Login fixtures now reject malformed hours, ASNs, and required identity fields before model fitting. Alert projections can hash user identifiers for analyst workflows, and aggregate summaries report severity and reason counts without returning raw identities.
