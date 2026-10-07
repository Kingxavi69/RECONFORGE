from reconforge.intelligence.diff import compare_scans


def test_compare_scans_detects_new_removed_and_changed():
    left = {
        "ports": [{"port": 80, "service": "http"}],
        "dns": {"A": ["1.1.1.1"]},
        "subdomains": ["www.example.com"],
        "technologies": ["nginx"],
        "findings": [{"title": "Missing header"}],
    }
    right = {
        "ports": [{"port": 443, "service": "https"}],
        "dns": {"A": ["2.2.2.2"]},
        "subdomains": ["api.example.com"],
        "technologies": ["Apache"],
        "findings": [{"title": "TLS expired"}],
    }

    diff = compare_scans(left, right)
    assert "new" in diff
    assert "removed" in diff
    assert "changed" in diff
