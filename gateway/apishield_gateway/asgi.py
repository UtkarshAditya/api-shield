"""ASGI entry point:  uvicorn gateway.apishield_gateway.asgi:app --port 8080"""
import logging

from .main import create_app

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)  # one log line per proxied request is too noisy
app = create_app()
