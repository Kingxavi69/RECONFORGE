from reconforge.intelligence.risk import calculate_risk_score


def test_risk_score_builds_reasonable_summary():
    findings = [
        {"severity": "low", "title": "Missing header"},
        {"severity": "medium", "title": "Exposed SSH"},
        {"severity": "high", "title": "Expired certificate"},
    ]

    score, level, reasons = calculate_risk_score(findings)
    assert score >= 0
    assert level in {"LOW", "MEDIUM", "HIGH"}
    assert reasons
