"""OpenAPI 3.x import: route matching, auth requirements and schemas for validation."""
from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
_PARAM = re.compile(r"\{([^/{}]+)\}")
_ID_SEGMENT = re.compile(r"^(?:\d+|[0-9a-fA-F]{8}-[0-9a-fA-F-]{27}|[0-9a-fA-F]{16,})$")


@dataclass
class Operation:
    method: str
    template: str
    requires_auth: bool = False
    path_params: dict = field(default_factory=dict)   # name -> schema
    query_params: list = field(default_factory=list)  # [{name, required, schema}]
    body_required: bool = False
    body_schemas: dict = field(default_factory=dict)  # content type -> schema
    validators: dict = field(default_factory=dict)    # cache used by the validation stage


def load_spec_file(path) -> dict:
    path = Path(path)
    with open(path, encoding="utf-8") as f:
        if path.suffix.lower() in (".yaml", ".yml"):
            return yaml.safe_load(f)
        return json.load(f)


def _template_regex(template: str) -> re.Pattern:
    parts, last = [], 0
    for m in _PARAM.finditer(template):
        parts.append(re.escape(template[last:m.start()]))
        parts.append(f"(?P<{re.sub(r'[^0-9a-zA-Z_]', '_', m.group(1))}>[^/]+)")
        last = m.end()
    parts.append(re.escape(template[last:]))
    return re.compile("^" + "".join(parts) + "/?$")


def fallback_template(path: str) -> str:
    """Without a spec, collapse ID-looking segments so events group per endpoint."""
    return "/".join("{id}" if _ID_SEGMENT.match(seg) else seg for seg in path.split("/")) or "/"


class ApiSpec:
    def __init__(self, spec: dict):
        self._root = spec or {}
        self._routes: list = []  # (regex, template, {METHOD: Operation})
        global_security = self._root.get("security")
        for template, item in (self._root.get("paths") or {}).items():
            item = self._deref(item)
            shared = item.get("parameters", [])
            ops = {}
            for method in HTTP_METHODS:
                raw = item.get(method)
                if raw is None:
                    continue
                # An operation's own "security" overrides the global one
                security = raw.get("security", global_security)
                op = Operation(method=method.upper(), template=template, requires_auth=bool(security))
                for p in shared + raw.get("parameters", []):
                    p = self._deref(p)
                    schema = self._deref(p.get("schema") or {})
                    if p.get("in") == "path":
                        op.path_params[p["name"]] = schema
                    elif p.get("in") == "query":
                        op.query_params.append(
                            {"name": p["name"], "required": bool(p.get("required")), "schema": schema}
                        )
                body = self._deref(raw.get("requestBody") or {})
                op.body_required = bool(body.get("required"))
                for ctype, media in (body.get("content") or {}).items():
                    op.body_schemas[ctype.lower()] = self._deref(media.get("schema") or {})
                ops[op.method] = op
            self._routes.append((_template_regex(template), template, ops))
        # Static paths win over templated ones: /users/me before /users/{id}
        self._routes.sort(key=lambda r: (len(_PARAM.findall(r[1])), -len(r[1])))

    def _deref(self, node, _stack=()):
        """Inline local $refs so each schema is self-contained."""
        if isinstance(node, list):
            return [self._deref(n, _stack) for n in node]
        if not isinstance(node, dict):
            return node
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/"):
            if ref in _stack:
                return {}  # recursive schema: accept anything below this point
            target = self._root
            for part in ref[2:].split("/"):
                target = target.get(part.replace("~1", "/").replace("~0", "~"), {})
            return self._deref(copy.deepcopy(target), _stack + (ref,))
        out = {k: self._deref(v, _stack) for k, v in node.items()}
        if out.get("nullable") is True and isinstance(out.get("type"), str):  # OpenAPI 3.0
            out["type"] = [out["type"], "null"]
        return out

    def match(self, method: str, path: str):
        """Return (operation or None, path_template or None, path params)."""
        known_template = None
        for regex, template, ops in self._routes:
            m = regex.match(path)
            if not m:
                continue
            if method in ops:
                return ops[method], template, m.groupdict()
            known_template = known_template or template
        return None, known_template, {}

    def __len__(self) -> int:
        return sum(len(ops) for _, _, ops in self._routes)
