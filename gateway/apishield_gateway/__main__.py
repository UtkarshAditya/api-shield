"""Run with:  python -m gateway.apishield_gateway   (from the repo root)"""
import os

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "gateway.apishield_gateway.asgi:app",
        host=os.environ.get("APISHIELD_HOST", "0.0.0.0"),
        port=int(os.environ.get("APISHIELD_PORT", "8080")),
    )
