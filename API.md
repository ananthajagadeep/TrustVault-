# TrustVault endpoint access matrix

All state-changing browser forms require a CSRF token. The app uses cookie sessions. Unauthorized document IDs intentionally return 404 to reduce document-existence disclosure.

| Method | Path | Who may call | Behavior |
|---|---|---|---|
| GET | `/` | Anonymous/authenticated | Landing page or redirect to workspace |
| GET, POST | `/register` | Anonymous | Create owner/viewer account; never creates admin |
| GET, POST | `/login` | Anonymous | Authenticate; successful and failed attempts audited |
| POST | `/logout` | Authenticated | End session |
| GET | `/dashboard` | Authenticated | List owned and granted documents |
| GET | `/documents` | Authenticated | Search only owned/granted documents by title/filename, owner, category, date |
| POST | `/upload` | Owner or admin | Upload validated file and metadata |
| GET | `/documents/{id}/download` | Owner or user with read/edit grant | Re-check current permission, audit, then download |
| POST | `/documents/{id}/edit` | Owner or user with edit grant | Edit title/category |
| POST | `/documents/{id}/delete` | Owner only | Soft-delete document and remove grants |
| GET | `/documents/{id}/permissions` | Owner only | List current grants |
| POST | `/documents/{id}/permissions` | Owner only | Grant or change read/edit access to active registered user |
| POST | `/documents/{id}/permissions/{user_id}/revoke` | Owner only | Revoke access |
| GET | `/admin/audit` | Admin only | View latest 500 audit events |
| GET | `/admin/audit/verify` | Admin only | Verify hash chain and record verification event |
| GET | `/admin/users` | Admin only | View user metadata |

## Permission semantics

- `admin`: audit and user metadata administration; no implicit permission to read document contents.
- `owner`: read/download, edit metadata, upload, grant/revoke, and soft-delete own documents.
- `viewer`: can read/download only when a named grant exists.
- `edit` grant: read/download plus title/category changes. It does not allow permission changes or deletion.
- Revocation removes the grant from SQLite. Each protected request checks the current grant; no signed download URL is issued.
