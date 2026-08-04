# 🛡️ AI SecOps Log Analyzer — Beginner's Guide (No Tech Background Needed)

**Project (Group 84):** Autonomous AI SecOps Log Analyzer: An Agentic Framework for Threat Profiling
**Made by:** Yash Nimbalkar & Darshan Nikrad

---

## 1. What is this project? (One minute version)

Imagine you own a big website and a security guard who watches every visitor's
**logbook** (a list of every request: who came, what they asked for, what they got).

- The guard gets **thousands of entries per hour**.
- Most are normal people. Some are **hackers trying to break in**.
- If the guard reports *everything* unusual, the boss gets thousands of useless
  alarms (this is called **alert fatigue** — real security teams have this problem!).

This project is a **smart automatic guard** that:

1. **Notices when something is mathematically weird** — like one computer making
   10× more requests than everyone else (using a number called a **Z-score**).
2. **Checks a rulebook of known attack patterns** — e.g. "10+ wrong passwords in
   5 minutes = brute-force attack".
3. **Asks an AI detective to look at the evidence** and decide:
   *"Is this a real attack, or just a Google bot / a curious visitor?"*
   Then it writes a **clear report card** for each suspicious visitor.

**In one line:** It automatically finds hackers in server logs and explains *why*
it thinks they're hackers — without drowning you in false alarms.

---

## 2. Why is this special? (The research idea)

| Approach | Strength | Weakness |
|---|---|---|
| Statistics only | Catches everything weird | Lots of **false alarms** (crawlers, bots, curious users) |
| Rules only (old-style IDS) | No false alarms on known attacks | **Misses** new/moderate attacks |
| **This project (hybrid)** | **Best of both** — catches all attacks, zero false alarms | — |

In our test: Statistics alone = 17 alerts (8 false). Rules = missed 1 attack.
**Our hybrid = 9 alerts, 9 correct, 0 false.** That result is the heart of your research paper.

---

## 3. What YOU have to do (input) — it's basically clicking buttons

### Option A — The website (easiest)
1. Open the dashboard (on your laptop it's `http://localhost:8000` — already
   running for you right now).
2. (Optional) change the **Seed** and **Window** numbers.
3. Click **▶ Launch Pipeline**.
4. That's it. Wait ~1 second.

**Want to test a real file of your own?** Drag & drop an access-log CSV
(`timestamp, src_ip, method, path, status, bytes, latency_ms, user_agent, dst_port`)
onto the "Drop an access log" box — the AI will triage it the same way.

### Option B — Terminal (for viva / showing off code)
```bash
python main.py demo                  # one-click demo (offline, $0)
python main.py evaluate --llm openai # same, but with a real GPT analyst
python main.py analyze --logs my.log # analyze your own log file
```

---

## 4. What you GET (output) — the report card

After the run you see:

1. **KPI cards** — F1 score, precision, recall, false positives, latency, cost.
   *Best number to quote: "Agentic F1 = 1.000" (perfect detection).*
2. **Comparison table** — shows stats-only vs rules vs the hybrid (your hybrid wins).
3. **Incident reports** — cards like:
   ```
   INC-0010 — CRITICAL 8.0 — "Suspected Brute-Force Attack on Login Endpoint"
     src 185.220.101.34 · T1110.001 · Credential Access
     Why: 100+ failed passwords in one window
     Do this: lock the account, add MFA, add CAPTCHA
   ```
   Each card = **severity** (CRITICAL/HIGH/MEDIUM), the **MITRE ATT&CK** attack ID
   (the standard language of cybersecurity), the **evidence**, and **what to do**.
4. **Charts & figures** — saved as PNGs in `outputs/figures/` for your paper.
5. **Files** — everything also saved in the `outputs/` folder:
   `metrics.json` (numbers), `reports/*.md` (human-readable reports), etc.

**What you DON'T need:** no data to prepare, no API key for the demo, no cost.

---

## 5. How to run it on your laptop (setup, once)

```bash
# 1. Need Python 3.10+ (we used 3.13) — already on your machine
# 2. Install the packages
pip install -r requirements.txt fastapi uvicorn python-multipart openai

# 3. Start the website
uvicorn web.main:app --host 0.0.0.0 --port 8000

# 4. Open your browser at http://localhost:8000
```

Optional — use a **real AI brain** instead of the built-in one:
- Get a free key: OpenAI (paid) or run **Ollama** locally (free, `ollama serve`).
- Set it in the dashboard dropdown, or `export OPENAI_API_KEY=sk-...`.

---

## 6. How to host it online — a LIVE website (free, ~10 minutes)

The project already ships with a **Dockerfile** and a **render.yaml** — hosting
companies read these automatically. **Easiest option: Render.com (free tier).**

### Step-by-step (Render.com)
1. **Create a GitHub account** (github.com) if you don't have one.
2. **Upload the folder:**
   - On github.com click **New repository** → name it `ai-secops-analyzer` → Create.
   - In the project folder on your computer open Terminal and run:
     ```bash
     git init
     git add -A
     git commit -m "Initial commit"
     git branch -M main
     git remote add origin https://github.com/YOUR_USERNAME/ai-secops-analyzer.git
     git push -u origin main
     ```
3. **Go to render.com** → click **Sign up** (free) → **New** → **Web Service**.
4. **Connect your GitHub** and pick the `ai-secops-analyzer` repo.
5. Render **auto-detects `render.yaml`** (Python runtime, free plan, health check).
6. Click **Deploy**. Wait ~2–3 minutes.
7. Done! You get a public URL like:
   `https://ai-secops-analyzer.onrender.com` — share it with anyone.

### Other free options
| Host | How | Notes |
|---|---|---|
| **Hugging Face Spaces** | New Space → **Docker** runtime → push code | Best for demo links, `*.hf.space` |
| **Railway.app** | `railway init` + `railway up` | Auto-detects the Dockerfile |
| **Fly.io** | `docker build -t secops . && fly deploy` | More control |

> The site works **fully offline by default** (the built-in AI is free and
> instant). Only enable the GPT analyst if you want, by setting `OPENAI_API_KEY`
> as an environment variable on the host.

---

## 7. Glossary (words you'll hear in the viva)

| Word | Simple meaning |
|---|---|
| **SOC** | Security Operations Center — the room where humans watch alarms |
| **Alert fatigue** | When there are so many false alarms that real ones get ignored |
| **IDS** | Intrusion Detection System — software that looks for attacks |
| **Z-score** | "How many standard deviations from normal" — a measure of weirdness |
| **Anomaly** | Something that doesn't fit the usual pattern |
| **MITRE ATT&CK** | The official encyclopedia of hacker techniques (T-code = one technique) |
| **LLM / Agent** | A smart AI that can read evidence and reason about it |
| **Brute force** | Trying millions of passwords until one works |
| **SQL injection** | Sneaking database commands into a website's search box |
| **XSS** | Sneaking scripts into a website to attack its visitors |
| **DDoS** | Flooding a site with traffic so it crashes |
| **Exfiltration** | Stealing data out of a system |
| **Port scan** | Knocking on every door to find open ones |
| **Precision** | Of the things you flagged, how many were real |
| **Recall** | Of the real attacks, how many you caught |
| **F1** | A single score balancing precision + recall (1.0 = perfect) |

---

## 8. Quick answers

**Do I need to write any code?** No. Everything is built.
**Does it cost money?** $0 (offline mode). GPT mode costs cents.
**Will it work in the viva without internet?** Yes — run it on your laptop, offline.
**Where's the proof it works?** `outputs/metrics.json`, `outputs/reports/`,
`docs/PAPER_OUTLINE.md` (your paper skeleton with the real numbers).
