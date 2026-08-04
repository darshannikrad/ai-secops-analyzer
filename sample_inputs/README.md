# 📂 Sample Input Logs — try the analyzer with different files

Drop any of these CSVs into the dashboard's **"Drop an access log"** box
(local `http://localhost:8000` or your live Render site) — or analyze them from
the terminal:

```bash
python main.py analyze --logs sample_inputs/clean_log.csv
```

All files use the analyzer's expected schema:

```
timestamp, src_ip, method, path, status, bytes, latency_ms, user_agent, dst_port
```

## The files & what to expect

| File | What's inside | Events | What the analyzer reports |
|---|---|---|---|
| `clean_log.csv` | Normal weekday traffic + search-engine bots. **No attacks.** | 546 | **0 threats** — a few "review" items at most. Proves the system does *not* cry wolf (no alert fatigue). |
| `brute_sqli_log.csv` | Brute-force login attempts, SQL-injection probes, XSS probes | 1,168 | **3 threats**: brute_force (8.0), sql_injection (9.5), xss (7.0) |
| `ddos_scan_log.csv` | DDoS request flood (3 bots) + port scanning | 863 | **2 threats**: ddos (7.0), port_scan (4.0) |
| `full_mixed_log.csv` | All 7 attack types (the paper's standard corpus, seed 7) | 2,825 | **9 threats**: brute_force, credential_stuffing, data_exfiltration, 3× ddos, port_scan, sql_injection, xss |

*(Numbers above were measured with the offline analyst on this machine —
yours may differ by ±1 review item, but threats are stable.)*

## How to regenerate

```bash
python sample_inputs/make_samples.py
```

This recreates the three synthetic files and copies the standard dataset as
`full_mixed_log.csv`. Seeds are fixed, so the files are reproducible.

## Tips for the demo / viva

- **"Does it produce false alarms?"** → upload `clean_log.csv`: zero threats.
- **"Show us a real catch"** → upload `brute_sqli_log.csv` and expand the
  CRITICAL incident: MITRE `T1190`, evidence timeline, recommended actions.
- **"What about scale?"** → upload `full_mixed_log.csv` (2,825 events, ~0.5 s).
- Uploaded files are analyzed in **detection mode** (no ground truth), so the
  dashboard shows incidents instead of the evaluation table — exactly how a
  SOC tool would be used on live traffic.
