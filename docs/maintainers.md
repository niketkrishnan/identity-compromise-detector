# Maintainer Notes

Keep the core module small and testable. New integrations should be optional,
authenticated, documented, and disabled in demo mode. Changes to thresholds,
data schemas, or security policies require regression tests.
