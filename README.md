# CareCircle

> **Catalyst 2026 Solo AI Hackathon**  
> Collaborative Elderly Care & Medication Management Platform

---

## 1. Overview
CareCircle is an accessible, collaborative elderly-care and medication-management platform designed to solve senior medication double-dosing and alleviate caregiver anxiety.

### Core Roles
* **Elder**: Simplified, high-contrast, large-touch interface for one-tap dose logging and clear pill identification.
* **Caregiver**: Prescription management, real-time shared dose ledger, and escalation resolution.
* **Family**: Reassuring, read-only adherence activity timeline and peace of mind.

---

## 2. Technical Stack & Deployment Architecture
* **Backend Framework**: Python 3.12 + FastAPI
* **Template Engine**: Jinja2 with semantic HTML5 & WCAG AA/AAA targets
* **Client Frontend**: Vanilla JavaScript (lightweight, zero bundle overhead)
* **Database**: Firebase Firestore (Spark Free Tier) with server-side service account credentials
* **Deployment Target**: Vercel Serverless Functions (`@vercel/python` Beta, Fluid Compute)

### Vercel Serverless & Fluid Compute Constraints
* **Function Runtime**: Serverless ASGI entrypoint in `api/index.py`.
* **Execution Duration**: Bounded by Vercel Fluid Compute limits on the Hobby plan (`maxDuration: 60s`, well below the 300s Hobby cap). API routes are designed to execute in sub-second durations.
* **Cron Frequency**: Native Vercel cron on Hobby is strictly capped at **once per 24 hours (daily)**. Sub-daily crons fail at build time.
* **Operational Reality of Escalations**:  
  Under the free-tier serverless architecture, missed-dose detection operates via **Just-In-Time (JIT) evaluation** triggered during dashboard access, client polling, or active sync. Escalation does not guarantee instant push notifications when no user is accessing the app.

---

## 3. Local Development Setup

```bash
# 1. Clone repository and navigate to folder
cd carecircle-catalyst

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment variables
cp .env.example .env

# 4. Start the local development server
uvicorn api.index:app --reload --port 8000
```

---

## 4. Running Tests

```bash
pytest tests/ -v
```
