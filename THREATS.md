# TrustVault threat model

This document describes the current prototype, its controls, and accepted gaps. Revisit it after every security-relevant change.

## Assets and trust boundaries

- Confidential file contents and document metadata.
- User identities, role assignments, document grants, and audit evidence.
- Trust boundary: browser input is untrusted. The Flask server and its filesystem/database are trusted only while the host is not compromised.
- Roles: **admin** can review audit events and user metadata; **owner** uploads and manages their own documents and grants; **viewer** can read documents explicitly granted to them. A grant of `edit` allows a recipient to read/download and edit title/category. Only the owner can grant/revoke or soft-delete. Admin has no implicit content access.

## Threats considered

| Threat | Control in this prototype | Residual risk / accepted limitation |
|---|---|---|
| Guess another document ID and download it | Every download calls `require_document_permission`; response is the same 404 for missing and unauthorized documents | Must preserve this check on every new route; add tests for every new endpoint |
| Call a hidden endpoint directly instead of using the UI | Authorization is enforced in Flask route handlers, not only in templates | Code review is still needed for future routes |
| Viewer submits an upload request manually | Upload route requires owner/admin role | Admin upload is permitted in this prototype; decide if production policy should forbid it |
| Read access is mistaken for edit access | Edit route requires owner/edit; delete is owner-only | Edit means metadata only; file replacement/versioning is not implemented |
| Former user keeps using access after revocation | No signed/public links; each download checks the current grants table | A file already downloaded or copied cannot be remotely recalled; this is inherent to downloaded files |
| User uploads executable or mismatched file | Extension allowlist, size limit, basic file-signature checks, random storage names, files outside `static/` | Signature checks are not antivirus and are not comprehensive content sanitization; DOCX/XLSX are only checked for ZIP header |
| Path traversal via filename | `secure_filename`; server-generated random storage name; send_from_directory | Keep stored filenames opaque; never accept a path from the request |
| SQL injection | Parameterized SQL for user input | Review any new SQL carefully |
| Cross-site request forgery | Flask-WTF CSRF protection on state-changing forms | API clients would need a defined CSRF/auth model; CSRF is disabled in automated tests only |
| Session theft / script access | HttpOnly and SameSite=Lax session cookies; Secure flag can be enabled for HTTPS | Secure flag is off for local HTTP; use HTTPS and set `TRUSTVAULT_HTTPS=1` in deployment |
| Brute-force login / credential stuffing | Password hashes; generic login failure message | Rate limiting, lockout, MFA, and password reset are not implemented |
| Malicious user self-registers as admin | Public registration only permits owner/viewer; admin is created by seed script | No audited admin role-change workflow yet; protect seed command and database |
| Audit rows are edited/deleted in SQLite | Each event hash includes previous hash and event fields; admin can run verification | Hash chain is not tamper-proof if an attacker can rewrite the whole DB and recompute hashes. Production needs remote append-only logging, signed checkpoints, and restricted DB access |
| Denied access is invisible | Denied document access and role failures are logged | Some failures before application code (reverse proxy/network errors) are outside this audit trail; logging failures must be monitored |
| Audit log leaks secrets | Details are deliberately limited; passwords and file contents are not logged | Emails and metadata are personal/business data; apply retention and access policy |
| Search leaks inaccessible documents | Search SQL limits results to owned or explicitly granted docs | Test all search filters and future facets for access scope |
| Deleted file remains reachable | Soft delete sets `deleted_at`; normal document lookup excludes deleted rows; grants are removed | Bytes remain in uploads for recovery and disk usage. A retention/purge job and backup deletion policy are not implemented |
| Race between revoke and download | Download authorization is checked on each request before sending the file | A download already in progress cannot reliably be recalled. Multi-process transactions and streaming semantics need deployment-specific review |
| Database/file inconsistency during upload | File is removed if DB/audit work raises | Crash windows can leave orphaned files; production needs a reconciliation job |
| Compromised app host reads all files | Files are outside static web root and routes authorize reads | Host compromise is out of scope; at-rest encryption, key management, isolation, and backups are not implemented |
| Public deployment uses default secret/demo credentials | README marks seed accounts as local-only; deployment must set secrets/passwords | The development fallback secret is unsafe for deployment; replace it before exposing the service |
| Denial of service via large uploads or many login attempts | 16 MB request limit | Rate limits, quotas, malware scanning, and infrastructure protections are not implemented |

## Audit design and evidence limitations

Audit records are SHA-256 hash-chained in insertion order. Each event contains the previous event hash and a hash of canonicalized event fields. The verification endpoint detects changes, reordering, or deletion within the current chain. It does **not** make SQLite append-only and does not defeat a database administrator who can rewrite all rows and recompute the chain. A production design should ship events to a separately administered append-only log or SIEM and periodically sign/anchor chain heads.

## Deliberately not built

- Public share links, email invitations, SSO, MFA, password reset, and external guest accounts.
- File versioning, content preview, malware scanning, DLP, encryption-at-rest/key rotation, legal holds, and automated retention purge.
- Complete admin account lifecycle management, rate limiting, operational alerting, and external audit anchoring.
- Production deployment is not complete until TLS, secrets, logging, backups, and hardened WSGI hosting are configured.
