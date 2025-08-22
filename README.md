# Cloudsine VT Scanner

## Overview
A lightweight web app that scans files with VirusTotal, shows a friendly verdict page, and (optionally) stores a history in Postgres.  
It’s built with **Go + Gin**, uses **HTML templates** and **static assets embedded via Go’s `embed`**, and exposes JSON endpoints for automation/export.  
Optional **“Explain”** uses Gemini to summarize results for non-technical users.

---

## Architecture at a Glance
- **Web server:** Gin with per-IP rate limiting (≈1 req / 2s, burst 3).  
- **Scanning flow:**
  1. SHA-256 precheck
  2. If known on VT → show report
  3. Else upload once, poll with backoff
  4. Fallback to hash report  
- **Explain (optional):** Sends a normalized JSON summary to Gemini (`gemini-1.5-flash`) for a layperson-friendly explanation.  
- **Database (optional):** If `DATABASE_URL` is set, app auto-connects to Postgres, applies schema, and persists scans/explanations.  
- **Frontend:** Upload UI with client-side SHA-256 pre-lookup, progress bar, malicious-only feed, CSV export, filename search, and clean result pages.

---

## Key Endpoints
- `GET /` and `/scan` — upload UI (+ recent scans if DB enabled)  
- `POST /upload` — handle uploads, run scan, redirect to result page  
- `GET /result/:id` — result by analysis ID  
- `GET /result/sha256/:sha` — result by file hash (permalink)  
- `GET /api/lookup?sha256=…` — hash precheck (skip upload if known)  
- `POST /explain` — generates Gemini explanation (by analysis_id or sha256)  
- `GET /api/result-json/<idOrSha>` — raw VT JSON (downloadable)  
- `POST /rescan` — re-analyze a known hash  
- `GET /history`, `/malicious`, `/api/search?q=…`, `/export.csv` — history & export APIs

---

## Configuration

Environment variables:
- `VT_API_KEY` **(required)** — VirusTotal API key
- `GEMINI_API_KEY` *(required)* — enables `/explain`
- `DATABASE_URL` *(required)* — Postgres DSN for persistence
- `MAX_UPLOAD_MB` *(optional)* — default is 25 MB
- `PORT` *(optional)* — default `8080`

---

## Database Schema
When `DATABASE_URL` is set, table `scans` is created/updated with columns:
- `sha256`, `filename`, `size_bytes`, `mime`
- `vt_analysis_id`, `vt_verdict`, `detection_ratio`
- `vt_json`, `explanation`, `stored_path`
- `scan_count`, `first_seen`, `last_seen`  

Includes helpful indexes & constraints.  
**Insert/Upsert** increments scan count & updates timestamps.

---

## Local Development

Prerequisites: Go 1.21+, VirusTotal API key. (Optional: Postgres for persistence)

```bash
# 1. Set env
export VT_API_KEY=your-key
export GEMINI_API_KEY=your-gemini-key      
export DATABASE_URL='postgres://user:pass@localhost:5432/vts?sslmode=disable'
export MAX_UPLOAD_MB=50

# 2. Run
go run .

# or build
go build -o vt-scanner
./vt-scanner

# 3. Visit
http://127.0.0.1:8080/
