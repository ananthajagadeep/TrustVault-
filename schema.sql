
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin','owner','viewer')),
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL UNIQUE,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    file_data BLOB,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT
);

CREATE TABLE IF NOT EXISTS grants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL
        REFERENCES documents(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
    permission TEXT NOT NULL CHECK(permission IN ('read','edit')),
    granted_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    UNIQUE(document_id, user_id)
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    happened_at TEXT NOT NULL,
    actor_id INTEGER,
    actor_email TEXT,
    action TEXT NOT NULL,
    document_id INTEGER,
    target_user_id INTEGER,
    outcome TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS access_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL
        REFERENCES documents(id) ON DELETE CASCADE,
    requester_id INTEGER NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
    requested_permission TEXT NOT NULL
        CHECK(requested_permission IN ('read', 'edit')),
    reason TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending', 'approved', 'rejected')),
    requested_at TEXT NOT NULL,
    decided_at TEXT,
    decided_by INTEGER REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_documents_owner
ON documents(owner_id);

CREATE INDEX IF NOT EXISTS idx_documents_category
ON documents(category);

CREATE INDEX IF NOT EXISTS idx_grants_user
ON grants(user_id);

CREATE INDEX IF NOT EXISTS idx_audit_time
ON audit_events(happened_at);

CREATE INDEX IF NOT EXISTS idx_access_requests_document_status
ON access_requests(document_id, status);

CREATE INDEX IF NOT EXISTS idx_access_requests_requester
ON access_requests(requester_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_one_pending_access_request
ON access_requests(document_id, requester_id)
WHERE status = 'pending';
