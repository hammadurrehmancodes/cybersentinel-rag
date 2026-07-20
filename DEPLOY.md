# CyberSentinel Copilot — Deployment Guide
## Zero to Running, Every Step

---

## Final Folder Structure

```
cybersentinel/
├── data/
│   ├── nist_800_61.md          ← NIST framework (edit to add sections)
│   └── log_patterns.json       ← Attack signatures (edit to add patterns)
│
├── chroma_storage/             ← Built by seed_db.py. Gitignore this.
│
├── copilot/
│   ├── __init__.py
│   ├── log_analyzer.py         ← Parses raw logs, zero AI
│   ├── security_copilot.py     ← RAG pipeline, read-only DB queries
│   ├── routes.py               ← FastAPI endpoints
│   └── report_generator.py     ← PDF export
│
├── seed_db.py                  ← Run once. Builds chroma_storage/
├── requirements.txt
├── .env                        ← Your secrets (never commit this)
└── main.py                     ← Your existing FastAPI entry point
```

---

## Step 1 — Get Your Free Groq API Key

1. Go to **https://console.groq.com**
2. Sign up (free)
3. Click "API Keys" → "Create API Key"
4. Copy the key — you will not see it again

Free tier: **14,400 requests per day** with Llama 3.3 70B.
More than enough for development and FYP demos.

---

## Step 2 — Set Up Your Environment File

```bash
# In your cybersentinel/ root folder:
cp .env.example .env
```

Open `.env` and fill in:

```env
GROQ_API_KEY=gsk_your_actual_key_here

# Your existing Supabase config
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your_anon_key

# These defaults work as-is
CHROMA_PATH=./chroma_storage
GROQ_MODEL=llama-3.3-70b-versatile
EMBEDDING_MODEL=all-MiniLM-L6-v2
```

---

## Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

First install takes 3-5 minutes. `sentence-transformers` downloads a
~90MB embedding model on first use — this is normal.

---

## Step 4 — Create `copilot/__init__.py`

```bash
touch copilot/__init__.py
```

Python needs this file to treat `copilot/` as a package.
Without it your imports will fail with `ModuleNotFoundError`.

---

## Step 5 — Build the Knowledge Base (Run Once)

```bash
python seed_db.py
```

Output you should see:
```
=======================================================
  CyberSentinel — Knowledge Base Seeder
=======================================================
  Reading NIST SP 800-61...
  Produced 14 NIST chunks.
  Reading log_patterns.json...
  Produced 8 log pattern chunks.
  Downloading MITRE ATT&CK STIX from GitHub...
  Extracted 100 MITRE ATT&CK techniques.

  Total chunks to index: 122
  Building vector database...
  Indexed 50/122 chunks...
  Indexed 100/122 chunks...
  Indexed 122/122 chunks...
  Done. Collection 'security_frameworks' has 122 documents.

=======================================================
  Seeding complete. You can now start the app.
  Database location: /path/to/cybersentinel/chroma_storage
=======================================================
```

### Offline mode (no internet):
```bash
python seed_db.py --skip-mitre
```

### Rebuild from scratch:
```bash
python seed_db.py --reset
```

---

## Step 6 — Wire Into Your Existing FastAPI

Open your `main.py` and add these lines:

```python
from fastapi import FastAPI
from copilot.routes import router as copilot_router

app = FastAPI(title="CyberSentinel API")

# Your existing routes here...

# Add the copilot router
app.include_router(
    copilot_router,
    prefix="/api/copilot",
    tags=["Security Copilot"]
)
```

---

## Step 7 — Start the Server

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

You should see:
```
[Copilot] Knowledge base ready — 122 documents.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

---

## Step 8 — Test Every Endpoint

### Health check
```bash
curl http://localhost:8000/api/copilot/health
```
Expected: `{"status": "online", "knowledge_base": "ready", ...}`

---

### Analyze logs
```bash
curl -X POST http://localhost:8000/api/copilot/analyze-logs \
  -H "Content-Type: application/json" \
  -d '{
    "log_text": "Jan 15 03:22:11 server kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.45 DST=10.0.0.1 DPT=22\nJan 15 03:22:12 server kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.45 DST=10.0.0.1 DPT=22\nJan 15 03:22:13 server kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.45 DST=10.0.0.1 DPT=22\nJan 15 03:22:14 server kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.45 DST=10.0.0.1 DPT=22\nJan 15 03:22:15 server kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.45 DST=10.0.0.1 DPT=22"
  }'
```

---

### Ask a question
```bash
curl -X POST http://localhost:8000/api/copilot/ask \
  -H "Content-Type: application/json" \
  -d '{"question": "What is an SSH brute force attack and what should I do?"}'
```

---

### Investigate an IP
```bash
curl -X POST http://localhost:8000/api/copilot/investigate-ip \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "185.220.101.45",
    "platform_data": {
      "abuseipdb_score": 95,
      "country": "Germany",
      "isp": "Tor Exit Node"
    }
  }'
```

---

### Download PDF report
```bash
curl -X POST http://localhost:8000/api/copilot/analyze-logs/pdf \
  -H "Content-Type: application/json" \
  -d '{"log_text": "your logs here"}' \
  --output report.pdf
```

---

## Connecting to Your Flutter Frontend

In your Flutter app, call the copilot like this:

```dart
// Analyze logs
final response = await http.post(
  Uri.parse('http://your-server:8000/api/copilot/analyze-logs'),
  headers: {'Content-Type': 'application/json'},
  body: jsonEncode({'log_text': rawLogContent}),
);

final data = jsonDecode(response.body);
// data['plain_english_summary'] → show in UI
// data['severity_overall']      → color code the alert
// data['playbook']              → render step list
```

---

## Updating the Knowledge Base Later

To add new NIST sections:
1. Edit `data/nist_800_61.md` — add a new `## Section: Your Title` block
2. Run `python seed_db.py --reset`

To add new attack patterns:
1. Edit `data/log_patterns.json` — add a new object to the `patterns` array
2. Run `python seed_db.py --reset`

The app code never needs to change.
This is the whole point of the separated architecture.

---

## Common Errors and Fixes

| Error | Fix |
|-------|-----|
| `ModuleNotFoundError: copilot` | Run `touch copilot/__init__.py` |
| `Collection security_frameworks does not exist` | Run `python seed_db.py` |
| `GROQ_API_KEY not set` | Check your `.env` file exists and has the key |
| `Connection refused on port 8000` | Make sure uvicorn is running |
| `sentence_transformers not found` | Run `pip install sentence-transformers` |
