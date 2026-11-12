FROM python:3.12-slim

WORKDIR /app

COPY learning/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY learning/apishield_learning ./apishield_learning
COPY admin_api/__init__.py admin_api/privacy.py ./admin_api/

ENV PYTHONPATH=/app \
    APISHIELD_REDIS_URL=redis://redis:6379/0 \
    APISHIELD_EVENT_STREAM=apishield:traffic \
    APISHIELD_LEARNING_CONSUMER_GROUP=learner

CMD ["python", "-m", "apishield_learning"]
