# CareCircle

> **Catalyst 2026 Solo AI Hackathon Submission**  
> **Challenge Vertical:** Healthcare & Senior Well-Being / Care Coordination  
> **Repository:** CareCircle Catalyst  

---

## 1. Overview & Problem Statement

### The Problem
Senior citizens managing complex chronic conditions frequently suffer from **medication mismanagement, unintended double-dosing, and missed critical doses**. Concurrently, family members and informal caregivers experience persistent **anxiety, friction, and fragmented communication** because there is no single authoritative, synchronized truth regarding whether a daily dose was actually taken.

### The Solution Approach
**CareCircle** is an accessible, collaborative care-coordination platform designed around the care circle model. It establishes:
1. **Differentiated, Accessible Personas**: Tailored user experiences for **Elders** (large touch targets, high-contrast, simple PIN login), **Caregivers** (circle management, administration, credential resets), and **Family Members** (status visibility and peace of mind).
2. **Strict Multi-Tenant Circle Isolation**: All operations and records are partitioned by care circle identifiers, ensuring complete data segregation.
3. **Defense-in-Depth Security**: Argon2id credential hashing, stateful session lifecycle with dual-tier timeouts, HMAC-SHA256 double-submit CSRF defense, and constant-time comparison guards.

---

## 2. Implemented Functionality (Phases 1–4)

* **Phase 1 — Foundation & Health Architecture**:
  * FastAPI application runtime configured for serverless execution.
  * Accessible, WCAG AA/AAA-targeted Jinja2 templates with High Contrast mode and font-scaling controls.
  * Comprehensive system health endpoint (`GET /api/health`) reporting environment and database status.

* **Phase 2 — Cloud Firestore Core & Tenant Security**:
  * Cloud Firestore backend with automatic local in-memory fallback for testing and development.
  * Server-side service account credential parsing (Base64 / JSON) never exposed to client code.
  * `CircleSecurityContext` enforcing application-level tenant isolation on queries and document writes.
  * Production safeguard preventing accidental in-memory fallback in live environments.

* **Phase 3 — Authentication & Identity Lifecycle**:
  * **Caregiver & Family Authentication**: Username and password login (`POST /auth/login`) with rate-limiting and temporary account lockout.
  * **Elder-Accessible Authentication (Option B)**: Senior-friendly 6-character Circle Code + Elder Name + 4-to-6 digit numeric PIN (`POST /auth/elder-login`).
  * **First-Circle Provisioning Wizard**: Bootstrap setup endpoint (`POST /auth/setup-circle`) protected by server-side `BOOTSTRAP_SECRET`.
  * **Argon2id Hashing**: Raw passwords, elder PINs, and emergency recovery keys are hashed using OWASP-recommended parameters; raw secrets are never stored.
  * **Opaque Stateful Sessions**: 32-byte cryptographically secure session tokens stored only as SHA-256 hashes; delivered via `HttpOnly`, `SameSite=Lax` cookies with dual-tier idle and absolute timeouts.
  * **Multi-Device Support & $O(1)$ Revocation**: Simultaneous sessions permitted; single logout revokes current device; password changes and deactivations increment `auth_version` to invalidate all active sessions across devices immediately.
  * **Emergency Recovery Flow**: Single-use 24-character recovery key for primary caregivers with atomic key rotation.
  * **CSRF Protection**: Cryptographic HMAC-SHA256 double-submit CSRF tokens and Origin/Referer verification on all state-changing endpoints.
  * **Sanitized Validation Errors**: Custom exception handler stripping raw credentials, PINs, and secrets from 422 error responses.

* **Phase 4 — Care Circle Management & Invitations**:
  * **Care Circle Overview**: Detailed circle data, elder profile, and active member counter (`GET /api/circle`, `GET /circle`).
  * **Circle Metadata Updates**: Primary Caregiver endpoint (`PATCH /api/circle`) updating circle name and elder profile with automatic display-name synchronization.
  * **Membership Roster**: Sanitized member listing (`GET /api/circle/members`, `GET /api/circle/members/{id}`).
  * **Soft Member Deactivation**: Primary Caregivers can deactivate members (`POST /api/circle/members/{id}/deactivate`), terminating their sessions immediately while preserving historical records.
  * **Sole Primary Caregiver Protection**: Invariant preventing deactivation of the last active primary caregiver.
  * **Secure Invitation Lifecycle**: Primary Caregivers can invite Caregivers or Family members (`POST /api/circle/invitations`); generating 32-byte opaque tokens with SHA-256 storage, 48-hour expiration, and single-use atomic redemption (`POST /api/invitations/accept`). Elders are strictly prohibited from link-based invitation.
  * **Public Safe Inspection**: Public endpoint (`GET /api/invitations/inspect`) and landing page (`GET /invite/accept`) for invitees.

---

## 3. Technology Stack

* **Backend**: Python 3.12, FastAPI, Pydantic v2, Starlette
* **Security & Crypto**: Argon2-cffi (Argon2id), hashlib (SHA-256), hmac, secrets
* **Database**: Google Cloud Firestore (Firebase Admin SDK) with zero-dependency in-memory test fallback
* **Templating & UI**: Jinja2, Semantic HTML5, Vanilla JavaScript, High-Contrast CSS
* **Testing**: Pytest, FastAPI TestClient, AnyIO
* **Deployment Target**: Vercel Serverless Functions (`@vercel/python`)

---

## 4. Local Setup & Execution

### Prerequisites
* Python 3.12+
* Git

### Installation
```bash
# 1. Clone repository
git clone <repository-url>
cd carecircle-catalyst

# 2. Create and activate a virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure local environment variables
cp .env.example .env

# 5. Start development server
uvicorn app.main:app --reload --port 8000
```
Visit `http://localhost:8000` in your browser.

### Running the Test Suite
```bash
pytest -v
```

---

## 5. Current Limitations & Incomplete Features (Roadmap)

To maintain absolute transparency for this Catalyst 2026 checkpoint:
* **Medication Scheduling & Dose Confirmation (Phase 5)**: Medication prescriptions, schedules, one-tap elder dose logging, and the atomic dose ledger are architected in models and repositories but **not yet active in UI/API routes**.
* **Missed-Dose Escalations (Phase 5)**: Automated escalation alerts and Just-In-Time (JIT) missed-dose checks are designed for Phase 5.
* **Gemini AI Integration (Phase 5)**: Care plan summaries, medication interaction checks, and natural-language adherence reports via Google Gemini API are planned for the upcoming Phase 5 milestone.
* **Phase 4 Test Harness Alignment**: Phase 1–3 tests pass at 100% (69 passed, 6 skipped). In Phase 4, the test harness fixture references `POST /api/auth/login` rather than the active `POST /auth/login` route; this test fixture alignment will be addressed in the next development cycle.
