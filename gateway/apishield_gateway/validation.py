"""Stage 4: validate path, query and body against the imported OpenAPI schema."""
from __future__ import annotations

import re

from jsonschema import Draft202012Validator

from .config import Settings
from .context import Decision, RequestContext

_INT = re.compile(r"^-?\d+$")
_NUM = re.compile(r"^-?\d+(\.\d+)?([eE][-+]?\d+)?$")


def _candidates(value: str) -> list:
    """A URL value is always text; these are the typed values it could stand for."""
    out = []
    if _INT.match(value):
        out.append(int(value))
    elif _NUM.match(value):
        out.append(float(value))
    if value.lower() in ("true", "false"):
        out.append(value.lower() == "true")
    out.append(value)
    return out


def _validator(op, key: str, schema: dict) -> Draft202012Validator:
    if key not in op.validators:
        op.validators[key] = Draft202012Validator(schema)
    return op.validators[key]


def _param_ok(validator: Draft202012Validator, schema: dict, values: list) -> bool:
    if schema.get("type") == "array":
        item_validator = Draft202012Validator(schema.get("items") or {})
        items = []
        for raw in values:
            good = [c for c in _candidates(raw) if item_validator.is_valid(c)]
            if not good:
                return False
            items.append(good[0])
        return validator.is_valid(items)
    return any(validator.is_valid(c) for c in _candidates(values[-1]))


def _fail(where: str, message: str, status: int = 400, code: str = "validation_failed") -> Decision:
    return Decision(status, code, message, hit=f"validation.{where}")


class ValidationStage:
    name = "validation"

    def __init__(self, settings: Settings):
        self.s = settings

    async def on_request(self, ctx: RequestContext):
        op = ctx.operation
        if op is None:
            if self.s.block_unknown_endpoints:
                return _fail("unknown_endpoint", "Endpoint is not in the API specification", 404,
                             "unknown_endpoint")
            return None

        for name, schema in op.path_params.items():
            raw = ctx.path_params.get(name)
            if raw is not None and schema and not _param_ok(_validator(op, f"path:{name}", schema), schema, [raw]):
                return _fail("path", f"Path parameter '{name}' has the wrong type or format")

        for param in op.query_params:
            name, schema = param["name"], param["schema"]
            values = ctx.query.get(name)
            if values is None:
                if param["required"]:
                    return _fail("query", f"Missing required query parameter '{name}'")
                continue
            if schema and not _param_ok(_validator(op, f"query:{name}", schema), schema, values):
                return _fail("query", f"Query parameter '{name}' has the wrong type or format")

        if not op.body_schemas:
            return None
        if not ctx.body:
            if op.body_required:
                return _fail("body", "Request body is required")
            return None
        ctype = ctx.header("content-type").split(";")[0].strip().lower()
        schema = op.body_schemas.get(ctype, op.body_schemas.get("*/*"))
        if schema is None:
            return _fail("content_type", f"Content-Type must be one of: {', '.join(sorted(op.body_schemas))}",
                         415, "unsupported_media_type")
        if ctype == "application/json" or ctype.endswith("+json"):
            if ctx.json_error:
                return _fail("body", "Request body is not valid JSON")
            error = next(_validator(op, f"body:{ctype}", schema).iter_errors(ctx.json), None)
            if error is not None:
                # Name the field and the failed check, never echo the submitted value.
                field = ".".join(str(p) for p in error.absolute_path) or "body"
                if error.validator == "required":
                    missing = [f for f in error.validator_value if f not in (error.instance or {})]
                    detail = f"missing required field(s): {', '.join(missing)}"
                else:
                    detail = f"failed the '{error.validator}' check"
                return _fail("body", f"Invalid request body: {field} {detail}")
        return None
