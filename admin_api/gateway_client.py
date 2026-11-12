"""Client for the gateway's control endpoints. The admin token is sent only in the
X-APIShield-Admin-Token request header; it is never logged or put in a response."""
from __future__ import annotations

import logging

import httpx

from .errors import APIError

log = logging.getLogger("apishield.admin.gateway")
TOKEN_HEADER = "X-APIShield-Admin-Token"


class GatewayClient:
    def __init__(self, base_url: str, token: str, transport: httpx.AsyncBaseTransport | None = None,
                 timeout: float = 3.0):
        self._token = token
        self._client = httpx.AsyncClient(base_url=base_url.rstrip("/"), transport=transport, timeout=timeout)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _call(self, method: str, path: str, *, json=None, ok_statuses=(200, 201, 204)) -> httpx.Response:
        if not self._token:
            raise APIError(503, "gateway_not_configured",
                           "The gateway admin token is not configured on the Admin API.")
        try:
            resp = await self._client.request(method, path, json=json, headers={TOKEN_HEADER: self._token})
        except httpx.HTTPError as exc:
            log.warning("gateway %s %s failed: %s", method, path, type(exc).__name__)
            raise APIError(502, "gateway_unreachable",
                           "The gateway is not reachable, so nothing was changed. Check that it is running.") from None
        if resp.status_code in ok_statuses:
            return resp
        message = _gateway_message(resp)
        if resp.status_code in (400, 422):
            raise APIError(422, "gateway_rejected", f"The gateway rejected the change: {message}")
        if resp.status_code in (401, 403, 404):
            # 404 too: the gateway hides its control endpoints until a token is configured.
            raise APIError(502, "gateway_auth_failed",
                           "The gateway refused the Admin API token. Check APISHIELD_ADMIN_TOKEN on both services.")
        raise APIError(502, "gateway_error", f"The gateway answered {resp.status_code}: {message}")

    async def health(self) -> dict:
        try:
            resp = await self._client.get("/_apishield/health")
            resp.raise_for_status()
            return resp.json()
        except (httpx.HTTPError, ValueError):
            raise APIError(502, "gateway_unreachable", "The gateway is not reachable.") from None

    async def list_rules(self) -> list:
        data = (await self._call("GET", "/_apishield/rules")).json()
        return data.get("rules", []) if isinstance(data, dict) else data

    async def upsert_rules(self, rules: list) -> None:
        await self._call("POST", "/_apishield/rules", json={"rules": rules})

    async def delete_rule(self, rule_id: str) -> None:
        # 404 means the gateway does not hold it as a runtime rule: already gone.
        await self._call("DELETE", f"/_apishield/rules/{rule_id}", ok_statuses=(200, 204, 404))

    async def set_mode(self, mode: str) -> None:
        await self._call("PUT", "/_apishield/mode", json={"mode": mode})


def _gateway_message(resp: httpx.Response) -> str:
    """Proxy errors use the gateway envelope; its control endpoints raise plain
    HTTPException, so they answer FastAPI's {"detail": "..."} instead."""
    try:
        body = resp.json()
    except ValueError:
        return f"HTTP {resp.status_code}"
    if isinstance(body, dict):
        if isinstance(body.get("error"), dict) and "message" in body["error"]:
            return str(body["error"]["message"])
        if isinstance(body.get("detail"), str):
            return body["detail"]
    return f"HTTP {resp.status_code}"
