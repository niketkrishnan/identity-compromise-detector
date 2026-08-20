# Testing Strategy

Unit tests cover deterministic logic, contract tests cover public imports,
fixture tests cover expected defensive behavior, and CI runs both tests and
the local evaluation command. Future benchmark tests should be separated from
fast regression tests.
