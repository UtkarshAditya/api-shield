import json
from pathlib import Path

import yaml

from .models import Endpoint

HTTP_METHODS = ("get", "post", "put", "patch", "delete")


def load_spec(path) -> dict:
    """Read an OpenAPI file (.json, .yaml or .yml) into a dictionary."""
    path = Path(path)
    with open(path, encoding="utf-8") as f:
        if path.suffix.lower() in (".yaml", ".yml"):
            return yaml.safe_load(f)
        return json.load(f)


def parse_endpoints(spec: dict) -> list[Endpoint]:
    """Turn the 'paths' section of the spec into a list of Endpoint objects."""
    global_security = spec.get("security")
    endpoints = []
    for path, item in spec.get("paths", {}).items():
        shared_params = item.get("parameters", [])
        for method in HTTP_METHODS:
            operation = item.get(method)
            if operation is None:
                continue
            # An operation's own "security" overrides the global one
            security = operation.get("security", global_security)
            params = []
            for p in shared_params + operation.get("parameters", []):
                if "name" not in p:  # skip unresolved $ref entries
                    continue
                params.append(
                    {
                        "name": p["name"],
                        "in": p.get("in", "query"),
                        "required": p.get("required", False),
                        "type": p.get("schema", {}).get("type", "string"),
                    }
                )
            endpoints.append(
                Endpoint(
                    method=method.upper(),
                    path=path,
                    params=params,
                    requires_auth=bool(security),
                )
            )
    return endpoints


def fill_path_params(endpoint: Endpoint) -> str:
    """Replace {placeholders} in the path with sample values."""
    path = endpoint.path
    for p in endpoint.params:
        if p["in"] == "path":
            sample = "1" if p["type"] in ("integer", "number") else "test"
            path = path.replace("{" + p["name"] + "}", sample)
    return path