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

$env:TRUSTVAULT_ADMIN_PASSWORD = "Choose-A-Strong-Admin-Password"
$env:TRUSTVAULT_OWNER_PASSWORD = "Choose-A-Strong-Owner-Password"
$env:TRUSTVAULT_VIEWER_PASSWORD = "Choose-A-Strong-Viewer-Password"

.\.venv\Scripts\python.exe seed.py
.\.venv\Scripts\python.exe app.py
```

Open `http://127.0.0.1:5000`.

### Local demo accounts

The seed script creates these local demo accounts using the passwords you set in the environment variables above:

- Admin: `admin@trustvault.local`
- Owner: `owner@trustvault.local`
- Viewer: `viewer@trustvault.local`

Existing accounts are not overwritten when the seed script runs again. Keep your passwords private, and never use demo credentials in a public deployment.

For a non-local environment, set unique values for:
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
