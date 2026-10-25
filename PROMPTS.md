# AI-assisted development log

This log records the actual interaction sequence for the initial prototype on 2026-10-21. These entries are all from the same day and do **not** replace the requirement to keep making dated entries and meaningful commits throughout the challenge week. Add a new entry after each real AI-assisted change; never invent commit hashes or claim a fix was committed when it was not.

## 2026-10-21 — Front-end design

- **Prompt / request:** The initial TrustVault Flask page looked plain; improve its HTML/CSS.
- **Produced:** A dark, security-themed landing page with navigation, a hero area, a document mockup, feature cards, and responsive styling.
- **What was wrong / missing:** It was only a visual front end. Buttons and sample files were not connected to working authentication or storage.
- **What changed next:** The follow-up request explicitly asked to connect the front end to the back end. No repository commit was made as part of this chat; add the actual commit URL after committing the work.

## 2026-10-21 — Flask back-end integration

- **Prompt / request:** Make the front-end controls work with a Flask back end.
- **Produced:** A first Flask/SQLite implementation with registration, login, upload/download, and sharing.
- **What was wrong / missing:** It did not meet the later challenge brief: no three-role model, no per-document read/edit permission model, no admin audit interface, no audit evidence, no search by all requested fields, and no adversarial authorization test suite.
- **What changed next:** The challenge brief became the implementation target and the project was redesigned around explicit authorization checks. No repository commit was made as part of this chat; add the actual commit URL after committing the work.

## 2026-10-21 — Authorization model and route review (security)

- **Prompt / request:** Adapt TrustVault to the supplied security challenge, especially least privilege, document-level permissions, revocation, and tests proving users cannot access documents they were not granted.
- **Produced:** Role checks, per-document read/edit grants, server-side permission checks on downloads/edits/deletes/permission routes, and tests for cross-user access and revocation.
- **What was wrong / what was checked:** Hiding links in templates is not authorization, so tests call routes directly. Admin was deliberately not given implicit document-content access. Revocation is checked against the database on every future request. A downloaded copy cannot be recalled.
- **What changed:** Added `require_document_permission`, owner-only permission management, and tests that check ungranted downloads, read-vs-edit, and revocation. The test suite has not been successfully executed in this environment because its dependencies are not installed here; install `requirements.txt` and run pytest before claiming tests pass. Commit URL: add the actual commit URL after committing.

## 2026-10-21 — Audit integrity review (security)

- **Prompt / request:** The challenge requires evidence of who accessed documents, including refused attempts, plus an admin view and a threat model.
- **Produced:** Audit events for authentication, upload/download attempts, metadata changes, deletion, grants/revocations, and role/access denials; SHA-256 previous-hash chaining and an admin verification view.
- **What was wrong / limitation found:** A hash chain detects many modifications but is not tamper-proof against an attacker who can rewrite the entire SQLite database and recompute every hash. The implementation does not yet anchor signed chain heads in a separately administered system. Some business writes and audit writes are separate transactions, so production-grade audit atomicity still needs work.
- **What changed:** Documented the limitation explicitly in `THREATS.md` and `README.md`; the admin UI warns that verification is not proof against full database rewrite. Production work should use an independently administered append-only log or SIEM and signed checkpoints. Commit URL: add the actual commit URL after committing.

## 2026-10-21 — Upload validation and test correction

- **Prompt / request:** Review the current app and adjust it to the detailed challenge, including upload validation and tests for unauthorized actions.
- **Produced:** An extension allowlist, size limit, opaque server-generated storage names, basic file signature checks, and tests for invalid file signatures and role restrictions.
- **What was wrong / limitation found:** Extension/signature checks are not malware scanning; Office files are only checked for a ZIP header. During review, the viewer-upload test initially expected a successful response even though the correct behavior is HTTP 403; the assertion was corrected. Syntax checks passed, but runtime tests remain unverified until dependencies are installed and pytest runs successfully.
- **What changed:** Corrected the viewer-upload test expectation and added the remaining caveats to `THREATS.md`. Commit URL: add the actual commit URL after committing.

## Reusable instructions / context

- Treat all browser input as untrusted.
- Authorization must be enforced in route handlers, never only in templates.
- Do not invent test results, deployment status, prompt history, or commit links.
- If a control is incomplete, document it as a limitation rather than claiming it is secure.
