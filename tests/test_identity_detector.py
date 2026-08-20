import pytest

from identity_detector import IdentityCompromiseDetector, LoginEvent, privacy_safe_report, summarize_alerts


def event(index: int, **overrides) -> LoginEvent:
    base = {
        "timestamp": f"2026-01-01T09:{index:02d}:00Z",
        "user_id": "u1",
        "device_id": "d1",
        "asn": 64500,
        "country": "IN",
        "hour": 9,
        "success": True,
        "privilege": "user",
    }
    base.update(overrides)
    return LoginEvent(**base)


def _events() -> list[LoginEvent]:
    return [event(1), event(2), event(3), event(4)]


def test_detector_explains_new_device_and_country():
    events = [event(1), event(2), event(3), event(4, user_id="u2", device_id="d2", asn=64501, country="US")]
    detector = IdentityCompromiseDetector(contamination=0.25).fit(events)
    alert = detector.score(4, event(5, device_id="new", asn=64999, country="DE", hour=3, success=False, privilege="admin"))
    assert alert.score > 0
    assert "new device for user" in alert.reasons
    assert "new country for user" in alert.reasons
    assert "failed authentication" in alert.reasons


def test_detector_returns_one_alert_per_event():
    events = [event(1), event(2), event(3), event(4)]
    alerts = IdentityCompromiseDetector().detect(events)
    assert len(alerts) == len(events)
    assert all(alert.user_id == "u1" for alert in alerts)


def test_login_event_rejects_invalid_identity_fields():
    with pytest.raises(ValueError, match="hour"):
        LoginEvent("2026-01-01T00:00:00Z", "u1", "d1", 64500, "US", 24, True)
    with pytest.raises(ValueError, match="asn"):
        LoginEvent("2026-01-01T00:00:00Z", "u1", "d1", 0, "US", 12, True)


def test_privacy_projection_does_not_expose_source_user_id():
    detector = IdentityCompromiseDetector().fit(_events())
    alert = detector.score(0, _events()[0])
    projected = alert.to_privacy_dict("test-salt")
    assert projected["user_id"] != alert.user_id
    assert len(projected["user_id"]) == 16


def test_custom_severity_thresholds_are_validated_and_applied():
    with pytest.raises(ValueError, match="thresholds"):
        IdentityCompromiseDetector(severity_thresholds=(0.8, 0.7))
    detector = IdentityCompromiseDetector(severity_thresholds=(0.2, 0.95)).fit(_events())
    alert = detector.score(0, _events()[0])
    assert alert.severity in {"low", "medium", "high"}


def test_alert_summary_aggregates_reasons_without_user_ids():
    detector = IdentityCompromiseDetector().fit(_events())
    alerts = [detector.score(index, event) for index, event in enumerate(_events())]
    summary = summarize_alerts(alerts)
    assert summary["alert_count"] == len(alerts)
    assert "severity_counts" in summary
    assert "user_id" not in summary


def test_privacy_safe_report_contains_aggregate_evidence_without_raw_ids():
    detector = IdentityCompromiseDetector().fit(_events())
    alerts = [detector.score(index, item) for index, item in enumerate(_events())]
    report = privacy_safe_report(alerts, "report-salt")
    assert report["summary"]["alert_count"] == len(alerts)
    assert report["privacy"]["raw_identifiers_included"] is False
    assert all(item["user_id"] != "u1" for item in report["alerts"])
