# SpectraShield

AI-powered phishing detection platform with:
- **FastAPI backend** for email/link risk analysis
- **React + Vite frontend** dashboard
- **Chrome extension** for popup scanning and Gmail risk indicators

## Project Structure

```text
SpectraShield/
├── backend/      # FastAPI API + threat analysis services
├── frontend/     # React dashboard UI
└── extension/    # Chrome extension (popup + Gmail content script)
```

## Features

- Email and URL phishing risk analysis via `POST /analyze`
- Risk scoring with explainable breakdown and threat category
- Threat-intel enriched URL insights and suspicious phrase highlighting
- Optional scan history (`GET /history`, `DELETE /history`)
- Privacy mode support (`private_mode: true`) to avoid storage
- Gmail row-level risk badges in the browser extension

## Prerequisites

- Python 3.10+
- Node.js 18+
- Supabase project (PostgreSQL) for online database mode
- Google Chrome (for extension testing)

## Quick Start

### 1) Backend (FastAPI)

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Create `backend/.env` before running backend:

```env
DB_BACKEND=postgres
DATABASE_URL=postgresql://postgres:<password>@<host>:5432/postgres

# Optional fallback mode
# DB_BACKEND=mongo
# MONGO_URI=mongodb://localhost:27017/
# MONGO_DB_NAME=spectrashield_db
```

Apply SQL bootstrap in Supabase SQL editor:

- [backend/sql/supabase_schema.sql](backend/sql/supabase_schema.sql)

Backend runs at: `http://localhost:8000`

### 2) Frontend (Vite)

```powershell
cd frontend
npm install
npm run dev
```

Frontend reads API base URL from `VITE_API_URL` (defaults to `http://localhost:8000`).

### 3) Chrome Extension

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the `extension/` folder

Use:
- **Popup**: paste email content and analyze
- **Gmail**: automatic risk badges on inbox rows (requires backend running)

## Core API Endpoints

- `POST /analyze` — Analyze email/link payload and return risk intelligence
- `GET /history` — Fetch stored scan history
- `GET /history/count` — Fetch total scan count (lightweight)
- `DELETE /history` — Clear all history
- `DELETE /history/{scan_id}` — Delete one scan by ID
- `GET /dashboard/top-brands` — Top impersonated brands with filters: `days`, `risk`, `source`, `limit`
- `GET /dashboard/risk-heatmap` — Heatmap cells from DB with filters: `days`, `risk`

## Notes

- Do **not** commit virtual environments (`venv/`, `.venv/`).
- Keep secrets and API keys out of git.
- Backend now supports both PostgreSQL (Supabase) and MongoDB via `DB_BACKEND`.

## License

No license file is currently included in this repository.
