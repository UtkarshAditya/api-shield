import httpx

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class UnsafeRequestError(Exception):
    """Raised when safe mode blocks a request that could change data."""


class ApiClient:
    def __init__(self, base_url: str, safe_mode: bool = True,
                 timeout: float = 5.0, http=None):
        self.base_url = base_url.rstrip("/")
        self.safe_mode = safe_mode
        self._http = http or httpx.Client(timeout=timeout)

    def is_allowed(self, method: str) -> bool:
        return (not self.safe_mode) or method.upper() in SAFE_METHODS

    def request(self, method: str, path: str, token: str | None = None, **kwargs):
        if not self.is_allowed(method):
            raise UnsafeRequestError(f"safe mode blocks {method.upper()} {path}")
        headers = dict(kwargs.pop("headers", None) or {})
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return self._http.request(
            method.upper(), self.base_url + path, headers=headers, **kwargs
        )