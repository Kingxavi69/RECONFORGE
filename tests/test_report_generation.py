from reconforge.reports.json_report import generate_json_report


def test_generate_json_report_contains_summary():
    payload = {
        "target": "example.com",
        "risk_level": "MEDIUM",
        "risk_score": 55,
        "dns": {"A": ["93.184.216.34"]},
        "ports": [{"port": 443, "state": "open"}],
    }

    report = generate_json_report(payload)
    assert report["target"] == "example.com"
    assert report["risk_level"] == "MEDIUM"
