import hashlib
import hmac

from admin_api.masking import MASK, mask_text, mask_value
from admin_api.privacy import pseudonymize

SALT = "unit-salt"


def _ref(value: str) -> str:
    return hmac.new(SALT.encode(), value.encode(), hashlib.sha256).hexdigest()[:8]


def test_pseudonymize_keeps_prefix_and_hashes_the_rest():
    assert pseudonymize("ip_203.0.113.7", SALT) == "ip_" + _ref("203.0.113.7")
    assert pseudonymize("user_alice", SALT) == "user_" + _ref("alice")


def test_bare_ip_matches_ip_caller():
    assert pseudonymize("203.0.113.7", SALT) == pseudonymize("ip_203.0.113.7", SALT)


def test_api_key_callers_pass_through():
    assert pseudonymize("key_1a2b3c4d", SALT) == "key_1a2b3c4d"


def test_deterministic_and_salted():
    a = pseudonymize("user_bob", SALT)
    assert a == pseudonymize("user_bob", SALT)
    assert a != pseudonymize("user_bob", "other-salt")
    assert len(a) == len("user_") + 8 and int(a[5:], 16) >= 0


def test_mask_text_secrets_and_pii():
    jwt_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    text = (f"token {jwt_token} for alice@example.com from 203.0.113.7 card 4111 1111 1111 1111 "
            'body {"password": "hunter2", "api_key": "abc"} Authorization: Bearer abc.def')
    out = mask_text(text)
    for raw in (jwt_token, "alice@example.com", "203.0.113.7", "4111 1111 1111 1111", "hunter2", "abc.def"):
        assert raw not in out
    assert MASK in out


def test_mask_value_recurses_and_replaces_sensitive_keys():
    out = mask_value({"payload": "' OR 1=1 --", "email": "a@b.co", "nested": [{"note": "mail x@y.io"}]})
    assert out["payload"] == "' OR 1=1 --"
    assert out["email"] == MASK
    assert "x@y.io" not in out["nested"][0]["note"]


def test_pseudonymize_text_leaves_path_templates_alone():
    from admin_api.masking import pseudonymize_text
    out = pseudonymize_text("GET /users/{user_id} by user_alice from ip_10.0.0.9 (user_1a2b3c4d)", SALT)
    assert "/users/{user_id}" in out
    assert "user_alice" not in out and "10.0.0.9" not in out
    assert "user_1a2b3c4d" in out  # already a pseudonym
