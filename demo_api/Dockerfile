# Build from the repo root:  docker build -f demo_api/Dockerfile -t apishield-demo-api .
FROM python:3.12-slim
WORKDIR /app
COPY demo_api/requirements.txt demo_api/requirements.txt
RUN pip install --no-cache-dir -r demo_api/requirements.txt
COPY demo_api demo_api
EXPOSE 8001
CMD ["uvicorn", "demo_api.main:app", "--host", "0.0.0.0", "--port", "8001"]
