FROM python:3.11-slim
WORKDIR /app/backend
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ /app/backend/
COPY docs/ /app/docs/
COPY data/public/ /app/data/public/
ENV DATA_DIR=/app/data PYTHONWARNINGS=ignore
# Regenerate the simulated corpus and train the anomaly baseline at build time (deterministic seeds).
RUN python -m synth.generate --out /app/data/captures --benign-per-family 40 \
 && python -m ipsec_analyzer.ml.train --manifest /app/data/captures/manifest.json
EXPOSE 8000
CMD ["uvicorn", "ipsec_analyzer.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
