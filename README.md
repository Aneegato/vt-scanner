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

```bash

Development Journey: Cloudsine VT Scanner
1. Initial Deployment to EC2

I started by setting up the VT Scanner directly on an EC2 instance.

Created an Ubuntu EC2 box and installed system dependencies (Go, certificates).

Deployed the Go code by manually copying it over, building on the server, and running it under systemd with environment variables in /etc/vt-scanner.env.

Verified that the app responded on port 8080.

Challenge:
At this stage, every small code change required me to rebuild on EC2 or manually re-upload files. This was slow and error-prone.

Solution:
I decided to switch to a workflow where I developed locally and only pushed to EC2 once I was satisfied.

2. Rsync to Local Development

To make development smoother, I pulled the code from EC2 back to my local machine using rsync:

rsync -avz -e "ssh -i ~/.ssh/cloudsine.pem" ubuntu@<EC2_IP>:~/apps/vt-scanner/ ./vt-scanner-local/


This gave me the exact same code I had running in production. From then on, I made changes locally, tested with go run main.go, and confirmed everything on localhost:8080.


3. Iterative Development

Once I had the code running locally, I iterated rapidly before pushing stable builds back to EC2.

a. File Upload Handling
The upload flow was designed with safety and validation in mind:

Upload directory: Files are stored under /var/tmp/vt-uploads. The app ensures this directory exists and recreates it if missing (os.MkdirAll(uploadDir, 0o700)), keeping it owner-only for security.

Size limit: Uploads are capped at 25 MB by default (MAX_UPLOAD_MB env variable can override this). Any file exceeding this size is rejected immediately.

Type validation: The app checks MIME types and extensions. While most formats are allowed for scanning, the validation prevents abuse (e.g., oversized files, malformed uploads).

SHA-256 hashing: As soon as the file is uploaded, a SHA-256 is computed. This enables:

Skipping duplicate uploads (client-side prehash check + server /api/lookup).

Reusing cached VirusTotal results where possible.

Temp storage cleanup: Files are saved temporarily and then removed after processing to avoid clutter or leaving malicious payloads on disk.

Together, these measures ensured that users could upload any file safely, while avoiding unnecessary VirusTotal calls.

b. Postgres Persistence

I added Postgres support so that scans and explanations could be saved and retrieved:

Schema auto-apply: On startup, if DATABASE_URL is set, the app automatically connects to Postgres and applies the schema (using embedded schema.sql or built-in fallback). This avoids manual migrations.

Data model: Each scan is persisted with:

sha256, filename, size_bytes, mime

vt_analysis_id, vt_verdict, detection_ratio

vt_json (raw VirusTotal JSON, stored as jsonb)

explanation (if Gemini is used)

scan_count, first_seen, last_seen

Operations:

Insert or upsert on scans (increment scan_count and update last_seen).
Search by filename (/api/search?q=...).
Export results as CSV (/export.csv, capped at 1000 rows).
Malicious-only feed (/malicious) for quick filtering.
Show first seen/last seen + scan count on result pages.

This allowed me to build history pages and a search feature that persisted across restarts, making the tool far more practical than a purely stateless API wrapper.

c. VirusTotal Integration

The scanner client (vt.go) was hardened for real-world reliability:
Conflict handling: If VirusTotal returns a 409 Conflict (scan already queued), the app waits and retries instead of failing.
Fallback: If polling fails, the app falls back to fetching a file report by hash.
Reanalysis: Users can trigger a re-scan explicitly via /rescan.
Verdict normalization: Raw VT engine results are distilled into a clean verdict: clean, suspicious, or malicious, along with a detection ratio.
This gave users fast responses when a hash was already known, while still supporting fresh uploads when necessary.

d. Gemini Explanations

I integrated Gemini 1.5-flash via Google’s generative-ai-go client:
After a scan, users can click “Explain”, which sends the normalized JSON result to Gemini.
Gemini returns a risk-rated, layperson-friendly explanation that avoids jargon and suggests next steps.
If Postgres is enabled, the explanation is saved alongside the scan record for future retrieval.
This bridged the gap between technical AV data and user-friendly guidance.

e. UI Enhancements

I refined the frontend templates (index.tmpl, result.tmpl) and CSS (styles.css, result.css):
Upload page:
Client-side SHA-256 precheck to skip uploads if known.
Progress bar with status messages.
Quick actions: View history, malicious-only feed, CSV export, filename search.
Result page:
Detection ratio and top engines flagged.
Buttons for Explain, Rescan, Copy link, Raw JSON view.
With DB enabled: shows first seen/last seen and scan count.

f. Deployment Back to EC2

Once changes were stable, I deployed by building locally and pushing the binary with rsync:

rsync -avz -e "ssh -i ~/.ssh/cloudsine.pem" ./vt-scanner ubuntu@<EC2_IP>:~/apps/vt-scanner/

Then I restarted the service:

sudo systemctl restart vt-scanner

This workflow gave me a fast develop locally → deploy tested builds to EC2 cycle, with systemd ensuring the app ran reliably in production.

4. HTTPS Setup

Challenge:
By default, the app ran on plain HTTP at port 8080. To make it production-ready, I needed HTTPS. This was tricky because:

Go app itself didn’t serve TLS.
Let’s Encrypt requires domain validation.
AWS EC2 only exposes raw ports without SSL termination.

Solution:
I fronted the Go app with Nginx on the EC2 instance:
Installed Nginx (sudo apt install nginx).
Configured a reverse proxy from 443 → 127.0.0.1:8080.

sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d mydomain.com

Opened ports 80 and 443 in the EC2 security group.

Now, traffic flows:

User (HTTPS) → Nginx (TLS termination) → Go app (localhost:8080)

5. Lessons Learned

Iterate locally first. Development was much faster when I switched to running everything on my laptop, only pushing binaries to EC2 once stable.
Rsync is essential. It made syncing code back and forth simple and predictable.
Automate with systemd. Having a unit file with Restart=always meant the app recovered from crashes.
HTTPS takes extra steps. EC2 alone doesn’t handle TLS, so Nginx + Let’s Encrypt was the cleanest solution.

Keep environment variables separate. Managing secrets (VT API key, Gemini API key, DB URL) in /etc/vt-scanner.env kept the systemd service clean.
