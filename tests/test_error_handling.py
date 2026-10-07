from reconforge.modules.ports import scan_ports


def test_ports_scan_handles_missing_nmap_gracefully():
    result = scan_ports("example.com", nmap_path="/definitely/missing/nmap")
    assert result["ok"] is False
    assert "not installed" in result["message"].lower() or "not found" in result["message"].lower()
