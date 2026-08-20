# Threat Model

## Protected capability

This project addresses privacy-conscious identity behavior analytics, anomaly scoring, risk explanations, and recommendation-only response.

## In-scope threats

The main in-scope threats are credential abuse, new devices, new networks, unusual access hours, failed authentication, and privilege anomalies.

## Trust boundaries

Inputs are untrusted telemetry, configuration, dependency metadata, identity
events, or application text depending on the project. The analysis layer is
read-only in demo mode. No external system is scanned or modified.

## Out of scope

Production access, credential collection, unrestricted tool execution, active
exploitation, and unauthorized data collection are out of scope.
