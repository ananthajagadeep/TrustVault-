# TrustVault — secure document sharing with an audit trail

Flask + SQLite security-focused prototype for a seven-day project challenge.

## Implemented

- Three roles: `admin`, `owner`, `viewer`.
- Per-document `read` and `edit` grants to named registered users.
- Server-side checks on protected download, edit, delete, permission, and search routes.
- Owner can grant, change, and revoke permissions.
- No public file URLs; files are outside `static/`; each download checks current access.
- Audit records for login success/failure, upload success/denial, download success/denial, edit, soft-delete, permission changes, and role denials.
- SHA-256 hash chain with admin verification endpoint.
- Search by document title/filename, owner, category, and date range, limited to documents the current user can access.
- Upload size and extension allowlist, random stored names, and basic signature checks.
- CSRF protection, password hashing, automated authorization tests.
- `THREATS.md`, `API.md`, `schema.sql`, and `PROMPTS.md`.

## Role model

- **Admin:** Can review audit events and user metadata. Does not automatically get document-content access.
- **Owner:** Can upload and manage their own documents, edit metadata, grant/revoke read/edit, and soft-delete.
- **Viewer:** Can download/read documents explicitly granted to them.
- **Edit grant:** Adds permission to update title/category. It does not allow permission changes or deletion.

## Local setup (Windows PowerShell)

Python 3.10+ recommended. PowerShell activation is optional; invoke the environment's Python directly if script activation is blocked.

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe seed.py
.\.venv\Scripts\python.exe app.py
```

Open `http://127.0.0.1:5000`.

### Local demo credentials

Seed script defaults (local development only; existing accounts are not overwritten):
- Admin: `admin@trustvault.local` / `TV_Admin_ChangeMe_2026!`
- Owner: `owner@trustvault.local` / `TV_Owner_ChangeMe_2026!`
- Viewer: `viewer@trustvault.local` / `TV_Viewer_ChangeMe_2026!`

Never deploy these default credentials. For a non-local environment, set unique environment variables before running `seed.py`:
- `TRUSTVAULT_ADMIN_PASSWORD`
- `TRUSTVAULT_OWNER_PASSWORD`
- `TRUSTVAULT_VIEWER_PASSWORD`

Also set a long random `TRUSTVAULT_SECRET_KEY` and `TRUSTVAULT_HTTPS=1` behind HTTPS. Use a production WSGI server; never expose Flask debug mode.

## Run automated tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Tests use a temporary SQLite database and temporary upload directory. They cover unauthorized download, grant/revoke, read-vs-edit, cross-owner permission manipulation, viewer upload denial, admin content-access separation, and invalid file signatures.

## Important security limitations

This is a learning prototype, not a production-ready confidential document system. Audit hash chaining detects many alterations but cannot stop an attacker with full database access from rewriting and recomputing the entire chain. For defensible evidence, ship audit events to an independently administered append-only service and anchor signed chain heads. Basic file-signature validation is not malware scanning. Encryption at rest, MFA, rate limiting, malware scanning, backup/restore testing, external audit anchoring, robust deployment hardening, and file versioning are not implemented.

See `THREATS.md`, `API.md`, and `PROMPTS.md` before demoing or deploying.
