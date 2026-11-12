# Build from the repo root:  docker build -f admin_api/Dockerfile -t apishield-admin-api .
# Stage 1 builds the dashboard against the real Admin API (no mocks); stage 2 serves it.
FROM node:20-alpine AS dashboard
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend ./
# Variables already in the environment take priority over frontend/.env
ENV VITE_USE_MOCKS=false VITE_API_BASE=/api
RUN npm run build

FROM python:3.12-slim
WORKDIR /app
COPY admin_api/requirements.txt admin_api/requirements.txt
RUN pip install --no-cache-dir -r admin_api/requirements.txt
# The gateway package validates and tests rules; the scanner package runs scans.
COPY gateway gateway
COPY scanner scanner
COPY demo_api/openapi.json demo_api/openapi.json
COPY admin_api admin_api
COPY --from=dashboard /frontend/dist /app/frontend/dist
ENV ADMIN_HOST=0.0.0.0 ADMIN_PORT=8000 ADMIN_STATIC_DIR=/app/frontend/dist \
    APISHIELD_OPENAPI_SPEC=/app/demo_api/openapi.json
EXPOSE 8000
CMD ["python", "-m", "admin_api"]
