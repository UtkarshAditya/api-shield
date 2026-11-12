"""python -m admin_api   (from the repo root)"""
import logging
import os
import re

import uvicorn

from .config import Config
from .main import create_app

logging.basicConfig(level=os.environ.get("ADMIN_LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")

_TOKEN_IN_QUERY = re.compile(r"(access_token=)[^&\s\"]+")


class RedactAccessToken(logging.Filter):
    """The SSE route takes the session JWT as ?access_token=; keep it out of access logs."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.args:
            record.args = tuple(_TOKEN_IN_QUERY.sub(r"\1[redacted]", a) if isinstance(a, str) else a
                                for a in record.args)
        record.msg = _TOKEN_IN_QUERY.sub(r"\1[redacted]", str(record.msg))
        return True


if __name__ == "__main__":
    logging.getLogger("uvicorn.access").addFilter(RedactAccessToken())
    uvicorn.run(create_app(Config.from_env()), host=os.environ.get("ADMIN_HOST", "127.0.0.1"),
                port=int(os.environ.get("ADMIN_PORT", "8000")), log_level="info")
