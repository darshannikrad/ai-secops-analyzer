# ─────────────────────────────────────────────────────────────────────
# AI SecOps Log Analyzer — web dashboard image
# Deploy anywhere: Render, Railway, Hugging Face Spaces, Fly.io, Docker
# ─────────────────────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# System deps (matplotlib needs a few libs on slim images)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Python deps first for layer caching (web/requirements.txt covers the API stack)
COPY requirements.txt web/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r web/requirements.txt

# Application source
COPY . .

# Bind to the platform-provided port (Render/Railway set $PORT)
ENV PORT=8000
EXPOSE 8000

# Seed the dataset at build time so first request is instant
RUN python -c "from web import service; service.ensure_seeded_data()"

CMD ["sh", "-c", "uvicorn web.main:app --host 0.0.0.0 --port ${PORT}"]
