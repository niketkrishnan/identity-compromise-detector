from __future__ import annotations

import json
from pathlib import Path

from identity_detector import IdentityCompromiseDetector, LoginEvent

ROOT = Path(__file__).parent
OUTPUT = ROOT / "artifacts" / "identity_results.json"


def main() -> None:
    rows = json.loads((ROOT / "data" / "events.json").read_text())
    events = [LoginEvent(**row) for row in rows]
    alerts = IdentityCompromiseDetector(contamination=0.2).detect(events)
    result = {
        "events": len(events),
        "high_or_medium_alerts": sum(alert.severity != "low" for alert in alerts),
        "alerts": [alert.to_dict() for alert in alerts],
        "data_note": "Local defensive fixture with synthetic identifiers; not a production benchmark.",
    }
    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
