FROM python:3.12-slim

WORKDIR /app

COPY learning/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY learning/apishield_learning ./apishield_learning
# Live mode uses the Admin API's tables (admin_api.models, admin_api.db) and the shared
# pseudonymization (admin_api.privacy); only those modules are imported, not FastAPI.
COPY admin_api ./admin_api

ENV PYTHONPATH=/app \
    APISHIELD_REDIS_URL=redis://redis:6379/0 \
    APISHIELD_EVENT_STREAM=apishield:traffic \
    APISHIELD_LEARNING_CONSUMER_GROUP=learner

CMD ["python", "-m", "apishield_learning"]
