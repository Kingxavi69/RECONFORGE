from reconforge.utils.validators import validate_target


def test_malformed_input_returns_error():
    result = validate_target("http://")
    assert result["valid"] is False
    assert result["error"]
