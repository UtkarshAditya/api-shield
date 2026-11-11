from pathlib import Path

from gateway.apishield_gateway.context import Decision
from gateway.apishield_gateway.normalize import decode_repeated, shape_hash
from gateway.apishield_gateway.spec import ApiSpec, fallback_template, load_spec_file

from .helpers import make_ctx

SPEC = ApiSpec(load_spec_file(Path(__file__).resolve().parents[2] / "demo_api" / "openapi.json"))


def test_double_encoding_is_decoded():
    assert decode_repeated("%2527") == "'"


def test_path_is_canonicalised():
    ctx = make_ctx(path="//users/./3/../3")
    assert ctx.path == "/users/3"


def test_null_byte_is_rejected_even_in_monitor_mode():
    decision = make_ctx(path="/users/3%00.json")
    assert isinstance(decision, Decision) and decision.status == 400 and decision.hard


def test_spec_gives_path_template_and_params():
    ctx = make_ctx(path="/users/42", spec=SPEC)
    assert ctx.path_template == "/users/{user_id}"
    assert ctx.path_params == {"user_id": "42"}
    assert ctx.operation.requires_auth is True


def test_unknown_path_falls_back_to_id_collapsing():
    assert fallback_template("/orders/123/items/9f8e7d6c5b4a39281706") == "/orders/{id}/items/{id}"
    assert make_ctx(path="/orders/123").path_template == "/orders/{id}"


def test_payload_text_holds_decoded_query_and_json_strings():
    ctx = make_ctx(method="POST", path="/comments", query="q=%27%20OR%20%271%27%3D%271",
                   json_body={"text": "<script>", "n": 1})
    assert "' OR '1'='1" in ctx.payload_text
    assert "<script>" in ctx.payload_text


def test_shape_hash_ignores_values_but_not_fields():
    a = shape_hash({}, {"username": "alice", "password": "x"})
    b = shape_hash({}, {"username": "bob", "password": "yyyy"})
    c = shape_hash({}, {"username": "bob", "password": "y", "role": "admin"})
    assert a == b and a != c


def test_bad_json_is_flagged_not_fatal():
    ctx = make_ctx(method="POST", path="/login", body=b"{not json",
                   headers={"Content-Type": "application/json"})
    assert ctx.json_error is True and ctx.json is None
