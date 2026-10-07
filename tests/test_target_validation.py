import pytest

from reconforge.utils.validators import validate_target


@pytest.mark.parametrize(
    "value",
    ["example.com", "127.0.0.1", "2001:db8::1", "https://example.com", "http://localhost:8000"],
)
def test_valid_targets(value):
    result = validate_target(value)
    assert result["valid"] is True
    assert result["normalized"]


@pytest.mark.parametrize(
    "value",
    [
        "",
        "http://",
        "bad host",
        "example..com",
        "https:///missing-host",
    ],
)
def test_invalid_targets(value):
    result = validate_target(value)
    assert result["valid"] is False
    assert "error" in result


def test_normalized_domain_uses_https_when_missing_scheme():
    result = validate_target("example.com")
    assert result["normalized"] == "https://example.com"
