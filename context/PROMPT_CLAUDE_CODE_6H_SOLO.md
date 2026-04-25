# PROMPT FOR CLAUDE CODE — SENTINEL (6H SOLO BUILD)

Read `CLAUDE_6H_SOLO.md` completely before writing any code. It is your only source of truth.

You are building **SENTINEL** — an AI-powered SOC Threat Intelligence PoC. The builder is solo with 6 hours. Every decision must optimize for **speed of implementation** and **demo impact**. No over-engineering.

---

## Build everything in this exact order. Do not skip steps. Do not reorder.

---

### STEP 1 — Project scaffold (do this first, takes 10 min)

Create this exact file structure:
```
sentinel/
├── CLAUDE_6H_SOLO.md   (already exists)
├── main.py
├── services.py
├── seed.py
├── .env
├── requirements.txt
├── start.sh
└── static/
    └── index.html
```

Create `requirements.txt`:
```
fastapi==0.111.0
uvicorn[standard]==0.30.1
httpx==0.27.0
scikit-learn==1.5.0
pandas==2.2.2
numpy==1.26.4
python-dotenv==1.0.1
python-multipart==0.0.9
```

Create `.env`:
```
ABUSEIPDB_API_KEY=
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3
```

---

### STEP 2 — seed.py (demo data, run once)

Write `seed.py` that:
1. Creates `sentinel.db` with the two tables from CLAUDE_6H_SOLO.md section 3
2. Checks if DB already has data — if yes, exit early (idempotent)
3. Inserts exactly **60 threat records** with this distribution:
   - 12 banking, 12 telecom, 12 healthcare, 12 government, 12 generic
   - Attack types: phishing, c2, lateral_movement, data_exfiltration, ransomware, port_scan, brute_force, malware
   - Use these real malicious IPs (vary the last octet): 185.220.101.x, 194.165.16.x, 45.142.212.x, 91.108.4.x, 77.73.133.x
   - Also include: domains like evil-c2.ru, malware-host.tk, darkweb-shop.onion
   - risk_score: random between 45-98, skewed high (use random.choices with weights)
   - first_seen: random datetime in last 7 days
   - mitre_tactic + mitre_technique: pre-filled from the MITRE_MAP in services section
   - confidence: 0.7 to 0.99
   - source: mix of "abuseipdb", "otx_feed", "seeded", "manual"
   - country: mix of RU, CN, KP, IR, UA, US, DE, FR
4. Inserts **20 alert records**: 5 critical, 8 high, 7 medium, linked to random threat IDs
5. Print summary: "Seeded: 60 threats, 20 alerts"

---

### STEP 3 — services.py (AI/ML pipeline)

Write `services.py` as a single file containing ALL of these — exact implementations from CLAUDE_6H_SOLO.md:

**A) `extract_iocs_regex(text: str) -> list[dict]`**
- All 6 regex patterns from section 5.1
- Returns list of `{type, value, confidence: 0.95}`
- Deduplicate by value

**B) `score_ioc(ioc_type: str, country: str, abuse_score: int) -> int`**
- Weighted formula from section 5.2
- Returns integer 0-100

**C) `map_to_mitre(attack_type: str) -> tuple[str, str]`**
- Full MITRE_MAP dict from section 5.3
- Returns (tactic, technique_id)

**D) `async call_llama(prompt: str) -> str`**
- Async httpx POST to Ollama
- 25s timeout
- On any error: return empty string

**E) `async extract_iocs_llm(text: str) -> list[dict]`**
- Exact prompt from section 5.4
- Parse JSON from response
- On error: return []

**F) `async generate_summary(threats: list) -> dict`**
- Exact prompt from section 5.4
- Parse JSON from response  
- On error: return the hardcoded fallback dict from section 5.4

**G) `async enrich_ip(ip: str, api_key: str) -> dict`**
- AbuseIPDB call with mock fallback
- Exact implementation from section 5.5

**H) `fit_isolation_forest(db_path: str)`**
- Load all threats from DB
- Build feature matrix: [risk_score, confidence, is_critical_country]
- Fit IsolationForest(contamination=0.1, random_state=42)
- Save model as global variable (in-memory, no pickle needed)
- Only run if >20 records exist

**I) `predict_anomaly(risk_score: int, confidence: float, country: str) -> bool`**
- Use fitted IsolationForest if available
- Fallback: return True if risk_score > 80

---

### STEP 4 — main.py (FastAPI backend)

Write `main.py` as a single FastAPI file:

**Setup:**
```python
from fastapi import FastAPI, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import sqlite3, json, csv, io
from services import *
from dotenv import load_dotenv
import os

load_dotenv()
app = FastAPI(title="SENTINEL SOC")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory="static"), name="static")

def get_db():
    return sqlite3.connect("sentinel.db", check_same_thread=False)
```

**Implement all endpoints from section 4 of CLAUDE_6H_SOLO.md:**

`GET /` → return FileResponse("static/index.html")

`GET /api/threats` → query params: limit=50, sector=None, severity=None
  - Build SQL with optional WHERE clauses
  - Return list of threat dicts

`GET /api/threats/stats` → return:
```json
{
  "total": 60,
  "by_sector": {"banking": 12, ...},
  "by_attack_type": {"phishing": 15, ...},
  "by_severity": {"critical": 10, ...},
  "avg_risk": 72.3
}
```
Where severity is derived: risk>80=critical, 60-80=high, 40-60=medium, <40=low

`GET /api/threats/top` → ORDER BY risk_score DESC LIMIT 10

`POST /api/ioc/extract` → body: `{"text": "..."}`
  - Run extract_iocs_regex() first
  - Then extract_iocs_llm() 
  - Merge results, deduplicate
  - For each IOC: score it, map MITRE
  - Insert into threats table
  - Return enriched list

`POST /api/ioc/enrich` → body: `{"ip": "..."}`
  - Call enrich_ip() with API key from env
  - Score the result
  - Map MITRE
  - Return enriched dict with: abuse_data, risk_score, mitre_tactic, is_anomaly

`POST /api/analysis/summary` → 
  - Fetch top 5 threats from DB
  - Call generate_summary()
  - Return {summary, severity, recommendation}

`GET /api/kpis` → return:
```json
{
  "iocs_processed": <count from threats>,
  "threats_detected": <count where risk_score > 60>,
  "critical_count": <count where risk_score > 80>,
  "mtta_seconds": 3.8,
  "sources": ["AbuseIPDB", "AlienVault OTX", "Local ML Engine"],
  "false_positive_rate": 11.7
}
```

`GET /api/export/json` → StreamingResponse of all threats as JSON
`GET /api/export/csv` → StreamingResponse of all threats as CSV

**On startup event:** call fit_isolation_forest("sentinel.db")

---

### STEP 5 — static/index.html (the entire frontend)

Write a single HTML file. It must:

**Head:**
- Import Chart.js from CDN: `https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js`
- Import Google Fonts: JetBrains Mono + IBM Plex Sans
- All CSS inline in `<style>` tag using the color variables from CLAUDE_6H_SOLO.md section 7

**Structure:**
```html
<body>
  <!-- Top nav bar -->
  <nav> SENTINEL logo | [Dashboard] [Investigate] [Reports] tabs </nav>
  
  <!-- KPI strip -->
  <div id="kpi-bar"> 4 metric boxes </div>
  
  <!-- Tab panels -->
  <div id="tab-dashboard"> ... </div>
  <div id="tab-investigate" hidden> ... </div>
  <div id="tab-reports" hidden> ... </div>
</body>
```

**Dashboard tab layout (CSS grid):**
- Left column (60%): Threat Timeline chart (last 7 days area chart) + MITRE Tactic horizontal bar chart
- Right column (40%): Alert feed (div with overflow-y scroll, max 8 items) + Executive Summary panel with Generate button
- Bottom full width: IOC table (20 rows, colored left border by risk)

**Investigate tab:**
- Textarea (4 rows, full width, dark styled, placeholder: "Paste threat report, log line, or any text...")
- [Extract IOCs] button → POST /api/ioc/extract → render colored tag pills per IOC
  - IP = red pill, domain = orange pill, hash = blue pill, CVE = green pill, URL = yellow pill
- Separator line
- Input field for IP + [Enrich] button → POST /api/ioc/enrich → show result card with: abuse score, country, risk score, MITRE tactic, anomaly flag
- Loading states: show "Analyzing..." text, not spinners

**Reports tab:**
- Simple table of all threats (fetch /api/threats?limit=100)
- Columns: IOC | Type | Risk | Attack Type | MITRE | Sector | Country | Time
- [Export JSON] button → window.location = '/api/export/json'
- [Export CSV] button → window.location = '/api/export/csv'

**JavaScript (inline `<script>` at bottom):**

```javascript
// On page load:
// 1. fetchKPIs() → populate KPI boxes with count-up animation (300ms)
// 2. fetchStats() → build Chart.js charts
// 3. fetchThreats() → populate IOC table
// 4. Poll fetchThreats() every 15000ms → update alert feed

// Tab switching:
// document.querySelectorAll('.tab-btn').forEach(btn => 
//   btn.onclick = () => showTab(btn.dataset.tab))

// Chart.js Timeline: AreaChart, last 7 days on X, threat count on Y
// Use data from /api/threats — group by date client-side

// Chart.js MITRE: HorizontalBar, tactics on Y, count on X
// Use data from /api/threats/stats → by_attack_type

// Generate Summary: 
//   show loading text → fetch POST /api/analysis/summary → display result
//   if fetch takes >8s → show fallback text

// Count-up animation:
// function animateCount(el, target) {
//   let start = 0;
//   const step = target / 30;
//   const timer = setInterval(() => {
//     start += step;
//     el.textContent = Math.floor(start);
//     if (start >= target) { el.textContent = target; clearInterval(timer); }
//   }, 10);
// }
```

**Visual requirements:**
- Background: #0a0e1a everywhere
- All cards: `background: rgba(15,22,41,0.85); border: 1px solid rgba(0,255,136,0.12); border-radius: 8px; padding: 16px;`
- Font: JetBrains Mono for numbers/values, IBM Plex Sans for labels
- KPI boxes: large number in green (#00ff88), label below in muted gray
- Pulsing green dot (CSS animation) next to "LIVE" text in the nav
- Risk score display: inline colored badge (red/orange/green) not just text
- Buttons: `background: transparent; border: 1px solid #00ff88; color: #00ff88; padding: 8px 16px; cursor: pointer; font-family: JetBrains Mono;`
- Buttons on hover: `background: rgba(0,255,136,0.1)`

---

### STEP 6 — start.sh

```bash
#!/bin/bash
set -e
echo "🛡️  SENTINEL starting..."
pip install -r requirements.txt -q
python seed.py
echo "✅ SENTINEL at http://localhost:8000"
echo "📖 API docs at http://localhost:8000/docs"
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

---

## IMPLEMENTATION RULES (non-negotiable)

1. **Never use blocking calls** in async endpoints — use `asyncio.to_thread()` for sqlite3 if needed, or just use sync endpoints (FastAPI handles it)
2. **Every endpoint must return valid JSON** even on error — use try/except everywhere
3. **LLaMA calls always have a fallback** — never let an LLaMA timeout crash the app
4. **The HTML file must work** by opening `http://localhost:8000` — no CORS issues
5. **seed.py must be idempotent** — run it 10 times, same result
6. **No external CSS frameworks** — pure inline CSS only in the HTML file

## Done when:
- [ ] `bash start.sh` works cleanly from zero
- [ ] Dashboard loads with charts and data
- [ ] Extract IOCs works on pasted text
- [ ] Generate Summary returns LLaMA output (or fallback)
- [ ] Export JSON/CSV downloads a real file
- [ ] No errors in terminal or browser console

## Start now. Build STEP 1 through STEP 6 in order. No clarifying questions.
