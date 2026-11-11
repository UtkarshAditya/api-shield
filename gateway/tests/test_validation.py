from pathlib import Path

from gateway.apishield_gateway.config import Settings
from gateway.apishield_gateway.spec import ApiSpec, load_spec_file
from gateway.apishield_gateway.validation import ValidationStage

from .helpers import make_ctx, run

SPEC = ApiSpec(load_spec_file(Path(__file__).resolve().parents[2] / "demo_api" / "openapi.json"))
ORDERS = ApiSpec({
    "openapi": "3.0.3",
    "paths": {
        "/orders": {
            "get": {"parameters": [
                {"name": "limit", "in": "query", "required": True,
                 "schema": {"type": "integer", "minimum": 1, "maximum": 100}},
                {"name": "tag", "in": "query", "schema": {"type": "array", "items": {"type": "string", "maxLength": 5}}},
            ]},
            "post": {"requestBody": {"required": True, "content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/Order"}}}}},
        },
    },
    "components": {"schemas": {"Order": {
        "type": "object", "required": ["sku", "qty"], "additionalProperties": False,
        "properties": {"sku": {"type": "string", "maxLength": 12},
                       "qty": {"type": "integer", "minimum": 1},
                       "note": {"type": "string", "nullable": True}},
    }}},
})


def _validate(spec=SPEC, settings=None, **kw):
    return run(ValidationStage(settings or Settings()).on_request(make_ctx(spec=spec, **kw)))


def test_valid_login_body_passes():
    assert _validate(method="POST", path="/login", json_body={"username": "alice", "password": "x"}) is None


def test_missing_required_field_names_the_field_not_the_value():
    decision = _validate(method="POST", path="/login", json_body={"username": "s3cret-value"})
    assert decision.status == 400 and decision.hit == "validation.body"
    assert "password" in decision.message and "s3cret-value" not in decision.message


def test_wrong_body_type_is_rejected():
    decision = _validate(method="POST", path="/login", json_body={"username": 5, "password": "x"})
    assert decision.status == 400 and "username" in decision.message


def test_invalid_json_and_missing_body_are_rejected():
    bad = _validate(method="POST", path="/login", body=b"{oops", headers={"Content-Type": "application/json"})
    assert bad.status == 400 and "JSON" in bad.message
    assert _validate(method="POST", path="/login").status == 400


def test_wrong_content_type_is_415():
    decision = _validate(method="POST", path="/login", body=b"username=a", headers={"Content-Type": "text/plain"})
    assert decision.status == 415 and decision.hit == "validation.content_type"


def test_path_param_type():
    assert _validate(path="/users/3") is None
    assert _validate(path="/users/abc").hit == "validation.path"


def test_query_params_required_type_and_range():
    assert _validate(ORDERS, path="/orders", query="limit=10") is None
    assert "limit" in _validate(ORDERS, path="/orders").message
    assert _validate(ORDERS, path="/orders", query="limit=ten").hit == "validation.query"
    assert _validate(ORDERS, path="/orders", query="limit=500").hit == "validation.query"


def test_array_query_param_validates_each_item():
    assert _validate(ORDERS, path="/orders", query="limit=1&tag=a&tag=b") is None
    assert _validate(ORDERS, path="/orders", query="limit=1&tag=toolong").hit == "validation.query"


def test_ref_schema_with_extra_field_and_nullable():
    ok = {"sku": "A1", "qty": 2, "note": None}
    assert _validate(ORDERS, method="POST", path="/orders", json_body=ok) is None
    extra = _validate(ORDERS, method="POST", path="/orders", json_body={**ok, "is_admin": True})
    assert extra.status == 400 and "additionalProperties" in extra.message


def test_unknown_endpoint_passes_unless_configured_to_block():
    assert _validate(path="/not-in-spec") is None
    decision = _validate(settings=Settings(block_unknown_endpoints=True), path="/not-in-spec")
    assert decision.status == 404
