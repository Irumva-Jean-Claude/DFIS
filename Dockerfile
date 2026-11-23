# ---- Stage 1: build the React frontend ----
FROM node:20-alpine AS frontend
WORKDIR /build/frontend-react
COPY frontend-react/package.json frontend-react/package-lock.json ./
RUN npm ci
COPY frontend-react/ ./
# vite.config.js writes the build to ../frontend-dist
RUN npm run build

# ---- Stage 2: Python backend + built UI + ML model ----
FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DFIS_DATA_DIR=/data
WORKDIR /app

COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend backend
COPY ml/models ml/models
COPY --from=frontend /build/frontend-dist frontend-dist

# Run as an unprivileged user; evidence and the database live on the /data volume.
RUN useradd --system --uid 1000 dfis && mkdir -p /data && chown -R dfis /data
USER dfis

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/ml/status')" || exit 1
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
