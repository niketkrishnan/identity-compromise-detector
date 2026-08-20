from identity_detector import IdentityCompromiseDetector, LoginEvent


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
