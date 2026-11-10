from pathlib import Path

from scanner.apishield_scanner.models import Endpoint
from scanner.apishield_scanner.spec import fill_path_params, load_spec, parse_endpoints

SPEC = Path(__file__).resolve().parents[2] / "demo_api" / "openapi.json"


def _endpoints():
    return parse_endpoints(load_spec(SPEC))


def test_parses_all_seven_endpoints():
    assert len(_endpoints()) == 7


def test_auth_flags_match_the_spec():
    protected = {e.path for e in _endpoints() if e.requires_auth}
    assert protected == {"/users/{user_id}", "/profile", "/admin/stats"}


def test_methods_are_uppercase():
    methods = {(e.method, e.path) for e in _endpoints()}
    assert ("POST", "/login") in methods and ("GET", "/search") in methods


def test_fill_path_params():
    ep = Endpoint(
        method="GET", path="/users/{user_id}",
        params=[{"name": "user_id", "in": "path", "required": True, "type": "integer"}],
    )
    assert fill_path_params(ep) == "/users/1"