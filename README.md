# Security Research Dashboard

A single-server FastAPI security researcher dashboard for storing nmap scan files, parsing CVE IDs, cross-checking Ubuntu or Red Hat CVE APIs, and saving versioned reports.

## Install

```bash
pip install fastapi uvicorn aiohttp aiosqlite python-multipart itsdangerous jinja2
```

## Run

```bash
uvicorn server:app --host 0.0.0.0 --port 8000 --reload
```

## Optional Groq AI CVE Classifier

Set this before running the server to enable AI status classification:

```bash
$env:GROQ_API_KEY="your_key_here"
```

Optional model override:

```bash
$env:GROQ_MODEL="llama-3.3-70b-versatile"
```

If `GROQ_API_KEY` is not set, the app uses a local fallback classifier. Saved reports include only CVEs marked as attention needed for the selected OS/version.

Open:

```text
http://localhost:8000
```

## Default Login

```text
username: admin
password: admin
```

The admin account can create researcher and viewer users. Researchers manage workspaces and scan files. Researchers and viewers can view saved reports.

## Files

```text
server.py
static/app.js
static/style.css
templates/index.html
uploads/
requirements.txt
```

`database.db` and uploaded scan files are generated locally and ignored by git.
