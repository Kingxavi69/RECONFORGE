from reconforge.modules.dns import normalize_dns_records


def test_normalize_dns_records_aggregates_types():
    raw = [
        {"type": "A", "value": "93.184.216.34"},
        {"type": "A", "value": "93.184.216.35"},
        {"type": "MX", "value": "mail.example.com"},
        {"type": "TXT", "value": "v=spf1 include:_spf.example.com"},
    ]

    normalized = normalize_dns_records(raw)
    assert normalized["A"] == ["93.184.216.34", "93.184.216.35"]
    assert normalized["MX"] == ["mail.example.com"]
    assert normalized["TXT"] == ["v=spf1 include:_spf.example.com"]
