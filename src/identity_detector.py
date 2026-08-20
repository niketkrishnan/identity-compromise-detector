"""Privacy-conscious identity anomaly detection for local authorized telemetry."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

import hashlib

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


@dataclass(frozen=True)
class LoginEvent:
    timestamp: str
    user_id: str
    device_id: str
    asn: int
    country: str
    hour: int
    success: bool
    privilege: str = "user"

    def __post_init__(self) -> None:
        if not self.user_id or not self.device_id or not self.country:
            raise ValueError("user_id, device_id, and country are required")
        if self.asn <= 0:
            raise ValueError("asn must be positive")
        if not 0 <= self.hour <= 23:
            raise ValueError("hour must be between 0 and 23")


@dataclass(frozen=True)
class IdentityAlert:
    event_index: int
    user_id: str
    score: float
    severity: str
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["reasons"] = list(self.reasons)
        return result

    def to_privacy_dict(self, salt: str = "local-demo") -> dict[str, Any]:
        """Return an analyst projection without exposing the source user identifier."""
        result = self.to_dict()
        digest = hashlib.sha256(f"{salt}:{self.user_id}".encode("utf-8")).hexdigest()
        result["user_id"] = digest[:16]
        return result


class IdentityCompromiseDetector:
    def __init__(self, contamination: float = 0.2, random_state: int = 42, severity_thresholds: tuple[float, float] = (0.4, 0.7)) -> None:
        medium_threshold, high_threshold = severity_thresholds
        if not 0.0 < medium_threshold < high_threshold <= 1.0:
            raise ValueError("severity thresholds must satisfy 0 < medium < high <= 1")
        self.medium_threshold = medium_threshold
        self.high_threshold = high_threshold
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=120,
            random_state=random_state,
        )
        self._fitted = False
        self.user_devices: dict[str, set[str]] = {}
        self.user_asns: dict[str, set[int]] = {}
        self.user_countries: dict[str, set[str]] = {}
        self.user_hours: dict[str, set[int]] = {}

    def _vectorize(self, event: LoginEvent) -> list[float]:
        known_devices = self.user_devices.get(event.user_id, set())
        known_asns = self.user_asns.get(event.user_id, set())
        known_countries = self.user_countries.get(event.user_id, set())
        known_hours = self.user_hours.get(event.user_id, set())
        return [
            float(event.success),
            float(event.device_id not in known_devices),
            float(event.asn not in known_asns),
            float(event.country not in known_countries),
            float(event.hour not in known_hours),
            float(event.privilege in {"admin", "owner"}),
            float(event.hour < 6 or event.hour > 22),
        ]

    def _update_baseline(self, events: list[LoginEvent]) -> None:
        for event in events:
            self.user_devices.setdefault(event.user_id, set()).add(event.device_id)
            self.user_asns.setdefault(event.user_id, set()).add(event.asn)
            self.user_countries.setdefault(event.user_id, set()).add(event.country)
            self.user_hours.setdefault(event.user_id, set()).add(event.hour)

    def fit(self, events: list[LoginEvent]) -> "IdentityCompromiseDetector":
        if len(events) < 4:
            raise ValueError("At least four events are required")
        self._update_baseline(events)
        matrix = self.scaler.fit_transform(np.asarray([self._vectorize(e) for e in events]))
        self.model.fit(matrix)
        self._fitted = True
        return self

    def score(self, index: int, event: LoginEvent) -> IdentityAlert:
        if not self._fitted:
            raise RuntimeError("Call fit() before score()")
        reasons: list[str] = []
        if not event.success:
            reasons.append("failed authentication")
        if event.device_id not in self.user_devices.get(event.user_id, set()):
            reasons.append("new device for user")
        if event.asn not in self.user_asns.get(event.user_id, set()):
            reasons.append("new network ASN for user")
        if event.country not in self.user_countries.get(event.user_id, set()):
            reasons.append("new country for user")
        if event.hour not in self.user_hours.get(event.user_id, set()):
            reasons.append("unusual access hour")
        if event.privilege in {"admin", "owner"}:
            reasons.append("privileged identity")
        vector = self.scaler.transform([self._vectorize(event)])
        raw = float(-self.model.score_samples(vector)[0])
        anomaly = float(np.clip((raw - 0.25) / 0.9, 0.0, 1.0))
        rule_score = min(0.15 * len(reasons), 1.0)
        total = round(float(np.clip(0.55 * rule_score + 0.45 * anomaly, 0.0, 1.0)), 4)
        severity = "high" if total >= self.high_threshold else "medium" if total >= self.medium_threshold else "low"
        return IdentityAlert(index, event.user_id, total, severity, tuple(dict.fromkeys(reasons)))

    def detect(self, events: list[LoginEvent]) -> list[IdentityAlert]:
        if len(events) < 4:
            raise ValueError("At least four events are required")
        # Use an initial chronological window as the learned baseline. This
        # prevents later suspicious events from redefining normal behavior.
        baseline_size = max(4, int(len(events) * 0.6))
        self.fit(events[:baseline_size])
        return [self.score(i, event) for i, event in enumerate(events)]


def summarize_alerts(alerts: list[IdentityAlert]) -> dict[str, Any]:
    """Return aggregate alert counts without returning raw identities."""
    severity_counts = {level: sum(alert.severity == level for alert in alerts) for level in ("high", "medium", "low")}
    reason_counts: dict[str, int] = {}
    for alert in alerts:
        for reason in alert.reasons:
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
    return {"alert_count": len(alerts), "severity_counts": severity_counts, "reason_counts": reason_counts}


def privacy_safe_report(alerts: list[IdentityAlert], salt: str = "local-demo") -> dict[str, Any]:
    """Return aggregate evidence plus pseudonymous alert records for analysts."""
    return {
        "summary": summarize_alerts(alerts),
        "alerts": [alert.to_privacy_dict(salt) for alert in alerts],
        "privacy": {"user_identifier": "salted-sha256-prefix", "raw_identifiers_included": False},
    }
