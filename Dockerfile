# Single-container image for hosting a public demo (used by render.yaml): the API also serves the built UI, with SQLite
# inside the container. For the full stack (PostgreSQL + API + nginx) use docker-compose.yml instead.
FROM node:20-alpine AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.11-slim
WORKDIR /app/backend
COPY backend/requirements.txt backend/constraints.txt ./
RUN pip install --no-cache-dir -r requirements.txt -c constraints.txt
COPY backend/ /app/backend/
COPY docs/ /app/docs/
COPY data/public/ /app/data/public/
COPY data/captures/lab/ /app/data/captures/lab/
COPY data/logs/ /app/data/logs/
ENV DATA_DIR=/app/data PYTHONWARNINGS=ignore UI_DIR=/app/ui
# Regenerate the simulated corpus and train the anomaly baseline at build time (deterministic seeds).
RUN python -m synth.generate --out /app/data/captures --benign-per-family 40 \
 && python -m ipsec_analyzer.ml.train --manifest /app/data/captures/manifest.json
COPY --from=ui /ui/dist /app/ui
EXPOSE 8000
# Hosts such as Render pass the port to listen on in $PORT.
CMD ["sh", "-c", "exec uvicorn ipsec_analyzer.api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
