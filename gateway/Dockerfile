# Build from the repo root:  docker build -f gateway/Dockerfile -t apishield-gateway .
FROM python:3.12-slim
WORKDIR /app
COPY gateway/requirements.txt gateway/requirements.txt
RUN pip install --no-cache-dir -r gateway/requirements.txt
COPY gateway gateway
COPY demo_api/openapi.json demo_api/openapi.json
ENV APISHIELD_HOST=0.0.0.0 APISHIELD_PORT=8080
EXPOSE 8080
CMD ["python", "-m", "gateway.apishield_gateway"]
