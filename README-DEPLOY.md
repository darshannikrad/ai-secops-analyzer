# Deploying the Dashboard Online

The web app is a single FastAPI service that serves both the API and the
frontend — no build step, no database, no Node.js. Any host that runs Python
works.

## Quick local run

```bash
pip install -r requirements.txt fastapi uvicorn python-multipart openai
uvicorn web.main:app --host 0.0.0.0 --port 8000
# open http://localhost:8000
```

## Option A — Render.com (easiest, free tier)

1. Push this folder to a GitHub/GitLab repo.
2. On render.com → **New → Web Service** → select the repo.
3. Render auto-detects `render.yaml` (runtime Python, free plan, health check
   at `/api/health`).
4. Deploy. In ~2 minutes you get a public URL like
   `https://ai-secops-analyzer.onrender.com`.
5. (Optional) Add `OPENAI_API_KEY` in the dashboard → Environment to enable
   the GPT analyst.

## Option B — Railway.app

```bash
railway login
railway init
railway up
```
Railway detects the Dockerfile automatically and supplies `$PORT`.

## Option C — Hugging Face Spaces (nice for demos)

Create a Space → **Docker** runtime → paste the `Dockerfile`. Push the folder;
HF builds and hosts it at `https://<user>-ai-secops-analyzer.hf.space`.

## Option D — Fly.io / any Docker host

```bash
docker build -t secops-analyzer .
docker run -p 8000:8000 secops-analyzer
```

## Environment variables

| Variable | Purpose |
|---|---|
| `PORT` | Port to bind (set automatically by Render/Railway) |
| `OPENAI_API_KEY` | Enables the LLM analyst (OpenAI-compatible) |
| `OPENAI_BASE_URL` | Point at Ollama / LM Studio / Groq / Together |

Without `OPENAI_API_KEY` the app runs fully **offline** with the deterministic
analyst — every feature still works at $0.00.

## API summary (also used by the frontend)

| Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | Dashboard UI |
| `/api/health` | GET | Liveness probe |
| `/api/demo` | POST | Run pipeline `{seed, minutes, provider}` → metrics + incidents |
| `/api/analyze` | POST | Upload access-log CSV → detection reports (multipart `file`) |
| `/api/last` | GET | Last run payload |
| `/api/figures/{name}` | GET | Publication figure PNGs |

## Notes for hosting

- The demo regenerates the seeded dataset on first boot (~1 s); data persists
  in the container filesystem per boot (fine for demos; production would mount
  a volume or use a queue).
- Uploaded logs are stored under `outputs/uploads/` for the session.
- Figure generation is wrapped in `secops/figures.py` and re-runs on each
  demo — no static assets to rebuild.
