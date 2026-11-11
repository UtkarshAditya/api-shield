from fastapi.testclient import TestClient

from demo_api.main import app
from scanner.apishield_scanner.client import ApiClient, UnsafeRequestError, login


def test_login_works_even_in_safe_mode():
    client = ApiClient("http://testserver", http=TestClient(app))
    token = login(client, "/login", "alice", "alice123")
    assert isinstance(token, str) and len(token) > 10


def test_request_still_blocks_other_posts():
    client = ApiClient("http://testserver", http=TestClient(app))
    try:
        client.request("POST", "/comments", json={})
        assert False, "should have raised"
    except UnsafeRequestError:
        pass