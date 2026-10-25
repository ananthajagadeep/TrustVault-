import hashlib
import json
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import (
    Flask, abort, flash, g, redirect, render_template, request,
    session, url_for, jsonify, send_file
)
from io import BytesIO
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("TRUSTVAULT_DATABASE", BASE_DIR / "trustvault.db"))
UPLOAD_DIR = Path(os.environ.get("TRUSTVAULT_UPLOAD_DIR", BASE_DIR / "uploads"))
MAX_CONTENT_LENGTH = 16 * 1024 * 1024
ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "txt", "docx", "xlsx"}
ROLES = {"admin", "owner", "viewer"}

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("TRUSTVAULT_SECRET_KEY", "dev-only-change-this-before-deployment"),
    MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("TRUSTVAULT_HTTPS") == "1",
)
CSRFProtect(app)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def connect_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db():
    with connect_db() as db:
        db.executescript("""
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
            document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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

        CREATE INDEX IF NOT EXISTS idx_access_requests_document_status
        ON access_requests(document_id, status);

        CREATE INDEX IF NOT EXISTS idx_access_requests_requester
        ON access_requests(requester_id);

        CREATE UNIQUE INDEX IF NOT EXISTS idx_one_pending_access_request
        ON access_requests(document_id, requester_id)
        WHERE status = 'pending';

        CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);
        CREATE INDEX IF NOT EXISTS idx_documents_category ON documents(category);
        CREATE INDEX IF NOT EXISTS idx_grants_user ON grants(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_events(happened_at);
        """)
        
        columns = {row["name"] for row in db.execute("PRAGMA table_info(documents)").fetchall()}
        if "file_data" not in columns:
            db.execute("ALTER TABLE documents ADD COLUMN file_data BLOB")


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def append_audit(action, outcome="success", document_id=None, target_user_id=None, detail=None, actor=None):
    """Append a hash-chained audit record. This detects edits/deletions but is not tamper-proof
    against an attacker who can rewrite the entire database and recompute the chain."""
    actor = actor if actor is not None else getattr(g, "user", None)
    actor_id = actor["id"] if actor else session.get("user_id")
    actor_email = actor["email"] if actor else None
    details = json.dumps(detail or {}, sort_keys=True, separators=(",", ":"))
    happened_at = utc_now()
    with connect_db() as db:
        previous = db.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
        previous_hash = previous["event_hash"] if previous else "GENESIS"
        payload = {
            "happened_at": happened_at,
            "actor_id": actor_id,
            "actor_email": actor_email,
            "action": action,
            "document_id": document_id,
            "target_user_id": target_user_id,
            "outcome": outcome,
            "detail_json": details,
            "previous_hash": previous_hash,
        }
        event_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        db.execute("""
            INSERT INTO audit_events
            (happened_at, actor_id, actor_email, action, document_id, target_user_id,
             outcome, detail_json, previous_hash, event_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (happened_at, actor_id, actor_email, action, document_id, target_user_id,
              outcome, details, previous_hash, event_hash))


def audit_attempt(action, outcome, document_id=None, target_user_id=None, detail=None):
    """Record denied actions with request context for the relevant document owner.

    Client IP and user-agent are investigative metadata, not proof of identity.
    A failed login without a document ID cannot reliably be attributed to a file owner.
    """
    details = dict(detail or {})
    if outcome == "denied" and (action.startswith("document.") or action.startswith("permission.")):
        details.setdefault("client_ip", request.remote_addr or "unknown")
        details.setdefault("user_agent", request.user_agent.string[:300] if request.user_agent else "unknown")
        details.setdefault("request_path", request.path)
    try:
        append_audit(action, outcome, document_id, target_user_id, details)
    except sqlite3.Error:
        # Fail closed on protected operations: callers still deny access.
        app.logger.exception("Could not write audit event")


def load_user(user_id):
    if not user_id:
        return None
    with connect_db() as db:
        return db.execute(
            "SELECT id,name,email,role,active FROM users WHERE id=?", (user_id,)
        ).fetchone()


@app.before_request
def attach_user():
    g.user = load_user(session.get("user_id"))
    if session.get("user_id") and (not g.user or not g.user["active"]):
        session.clear()
        g.user = None


@app.context_processor
def template_user():
    return {"current_user": getattr(g, "user", None)}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            audit_attempt("route.access", "denied", detail={"path": request.path, "reason": "not_authenticated"})
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def roles_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if g.user["role"] not in roles:
                audit_attempt("role.denied", "denied", detail={"path": request.path, "required_roles": roles})
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def get_document(document_id, include_deleted=False):
    query = "SELECT * FROM documents WHERE id=?"
    if not include_deleted:
        query += " AND deleted_at IS NULL"
    with connect_db() as db:
        return db.execute(query, (document_id,)).fetchone()


def permission_for(document_id, user_id):
    """Return owner/edit/read/None. Admin does not get implicit content access."""
    document = get_document(document_id)
    if not document:
        return None
    if document["owner_id"] == user_id:
        return "owner"
    with connect_db() as db:
        grant = db.execute(
            "SELECT permission FROM grants WHERE document_id=? AND user_id=?",
            (document_id, user_id)
        ).fetchone()
    return grant["permission"] if grant else None


def require_document_permission(document_id, minimum="read"):
    """Every document endpoint calls this server-side check; edit includes read."""
    if not g.user:
        audit_attempt("document.access", "denied", document_id, detail={"reason": "not_authenticated"})
        abort(401)
    document = get_document(document_id)
    permission = permission_for(document_id, g.user["id"])
    allowed = permission is not None and (minimum == "read" or permission in ("owner", "edit"))
    if not document or not allowed:
        audit_attempt(
            "document.access", "denied", document_id,
            detail={"required": minimum, "reason": "not_found_or_not_granted"}
        )
        # Same response for nonexistent and unauthorized document IDs.
        abort(404)
    return document, permission


def allowed_extension(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_signature(filename, data):
    """Basic content checks for common types. This is not a malware scanner."""
    ext = filename.rsplit(".", 1)[1].lower()
    if not data:
        return False
    if ext == "pdf":
        return data.startswith(b"%PDF-")
    if ext in ("jpg", "jpeg"):
        return data.startswith(b"\xff\xd8\xff")
    if ext == "png":
        return data.startswith(b"\x89PNG\r\n\x1a\n")
    if ext == "txt":
        try:
            data.decode("utf-8")
            return True
        except UnicodeDecodeError:
            return False
    if ext in ("docx", "xlsx"):
        # Office Open XML files are ZIP containers.
        return data.startswith(b"PK\x03\x04")
    return False


@app.route("/")
def home():
    if g.user:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    # Public self-registration can only create owner/viewer accounts, never admins.
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "owner").strip()
        if role not in ("owner", "viewer"):
            role = "owner"
        if not name or not email or len(password) < 10:
            flash("Enter your name and email, and use a password of at least 10 characters.", "error")
            return render_template("register.html")
        try:
            with connect_db() as db:
                db.execute(
                    "INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                    (name, email, generate_password_hash(password), role, utc_now())
                )
                new_id = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
            append_audit("user.register", actor={"id": new_id, "email": email}, detail={"role": role})
            flash("Account created. You can now log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            audit_attempt("user.register", "denied", detail={"reason": "duplicate_email"})
            flash("An account with that email already exists.", "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with connect_db() as db:
            user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and user["active"] and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            g.user = load_user(user["id"])
            append_audit("auth.login", actor=g.user, detail={"method": "password"})
            flash("Welcome back.", "success")
            return redirect(url_for("dashboard"))
        audit_attempt("auth.login", "denied", detail={"email": email, "reason": "invalid_credentials_or_inactive"})
        flash("Email or password is incorrect.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    append_audit("auth.logout")
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


@app.route("/dashboard")
@login_required
def dashboard():
    user_id = g.user["id"]
    with connect_db() as db:
        owned = db.execute("""
            SELECT d.*, (SELECT COUNT(*) FROM grants gr WHERE gr.document_id=d.id) AS grant_count
            FROM documents d WHERE d.owner_id=? AND d.deleted_at IS NULL
            ORDER BY d.updated_at DESC
        """, (user_id,)).fetchall()
        shared = db.execute("""
            SELECT d.*, u.name AS owner_name, u.email AS owner_email, gr.permission
            FROM grants gr JOIN documents d ON d.id=gr.document_id
            JOIN users u ON u.id=d.owner_id
            WHERE gr.user_id=? AND d.deleted_at IS NULL
            ORDER BY d.updated_at DESC
        """, (user_id,)).fetchall()
        denied_attempts = db.execute("""
            SELECT a.*, d.title AS document_title
            FROM audit_events a JOIN documents d ON d.id=a.document_id
            WHERE d.owner_id=? AND a.outcome='denied'
              AND a.action IN ('document.access','document.download','document.edit','document.delete','permission.list','permission.grant','permission.revoke')
            ORDER BY a.id DESC LIMIT 100
        """, (user_id,)).fetchall()
    return render_template("dashboard.html", documents=owned, shared_documents=shared,
                           denied_attempts=denied_attempts)


@app.route("/documents")
@login_required
def search_documents():
    query = request.args.get("q", "").strip()[:100]
    category = request.args.get("category", "").strip()[:80]
    owner = request.args.get("owner", "").strip()[:100]
    start_date = request.args.get("start_date", "").strip()
    end_date = request.args.get("end_date", "").strip()

    sql = """
      SELECT DISTINCT d.*, u.name AS owner_name, u.email AS owner_email
      FROM documents d JOIN users u ON u.id=d.owner_id
      LEFT JOIN grants gr ON gr.document_id=d.id
      WHERE d.deleted_at IS NULL AND (d.owner_id=? OR gr.user_id=?)
    """
    params = [g.user["id"], g.user["id"]]
    if query:
        sql += " AND (d.title LIKE ? OR d.original_name LIKE ?)"
        params.extend([f"%{query}%", f"%{query}%"])
    if category:
        sql += " AND d.category LIKE ?"
        params.append(f"%{category}%")
    if owner:
        sql += " AND (u.name LIKE ? OR u.email LIKE ?)"
        params.extend([f"%{owner}%", f"%{owner}%"])
    if start_date:
        sql += " AND substr(d.created_at,1,10) >= ?"
        params.append(start_date)
    if end_date:
        sql += " AND substr(d.created_at,1,10) <= ?"
        params.append(end_date)
    sql += " ORDER BY d.updated_at DESC"
    with connect_db() as db:
        results = db.execute(sql, params).fetchall()
    return render_template("search.html", documents=results, q=query, category=category,
                           owner=owner, start_date=start_date, end_date=end_date)


@app.route("/upload", methods=["POST"])
@roles_required("owner", "admin")
def upload():
    file = request.files.get("document")
    title = request.form.get("title", "").strip()[:160]
    category = request.form.get("category", "").strip()[:80] or "Uncategorised"
    if not file or not file.filename:
        audit_attempt("document.upload", "denied", detail={"reason": "missing_file"})
        flash("Choose a file before uploading.", "error")
        return redirect(url_for("dashboard"))
    original_name = secure_filename(file.filename)
    if not original_name or not allowed_extension(original_name):
        audit_attempt("document.upload", "denied", detail={"filename": original_name, "reason": "extension"})
        flash("File type is not allowed.", "error")
        return redirect(url_for("dashboard"))
    data = file.read(MAX_CONTENT_LENGTH + 1)
    if len(data) > MAX_CONTENT_LENGTH:
        audit_attempt("document.upload", "denied", detail={"filename": original_name, "reason": "size"})
        flash("Maximum upload size is 16 MB.", "error")
        return redirect(url_for("dashboard"))
    if not validate_signature(original_name, data):
        audit_attempt("document.upload", "denied", detail={"filename": original_name, "reason": "content_signature"})
        flash("File content does not match its extension or is empty.", "error")
        return redirect(url_for("dashboard"))
    if not title:
        title = original_name
    stored_name = uuid.uuid4().hex
    digest = hashlib.sha256(data).hexdigest()
    now = utc_now()
    try:
        with connect_db() as db:
            cursor = db.execute("""
              INSERT INTO documents(owner_id,title,category,original_name,stored_name,size_bytes,sha256,file_data,created_at,updated_at)
              VALUES(?,?,?,?,?,?,?,?,?,?)
            """, (g.user["id"], title, category, original_name, stored_name, len(data), digest, sqlite3.Binary(data), now, now))
            document_id = cursor.lastrowid
        append_audit("document.upload", document_id=document_id,
                     detail={"title": title, "category": category, "size_bytes": len(data), "sha256": digest})
    except Exception:
        raise
    flash("Document uploaded and stored in the database.", "success")
    return redirect(url_for("dashboard"))


@app.route("/documents/<int:document_id>/download")
@login_required
def download_document(document_id):
    document, permission = require_document_permission(document_id, "read")
    if document["file_data"] is None:
        append_audit("document.download", "error", document_id, detail={"reason": "file_missing_or_legacy_file"})
        abort(404)
    # Access is checked on every request before bytes are read from the database.
    append_audit("document.download", document_id=document_id,
                 detail={"permission": permission, "sha256": document["sha256"]})
    return send_file(BytesIO(document["file_data"]), as_attachment=True,
                     download_name=document["original_name"])


@app.route("/documents/<int:document_id>/edit", methods=["POST"])
@login_required
def edit_document(document_id):
    document, permission = require_document_permission(document_id, "edit")
    title = request.form.get("title", "").strip()[:160]
    category = request.form.get("category", "").strip()[:80]
    if not title or not category:
        flash("Title and category are required.", "error")
        return redirect(url_for("dashboard"))
    with connect_db() as db:
        db.execute("UPDATE documents SET title=?, category=?, updated_at=? WHERE id=?",
                   (title, category, utc_now(), document_id))
    append_audit("document.edit", document_id=document_id,
                 detail={"old_title": document["title"], "new_title": title,
                         "old_category": document["category"], "new_category": category,
                         "permission": permission})
    flash("Document details updated.", "success")
    return redirect(url_for("dashboard"))


@app.route("/documents/<int:document_id>/delete", methods=["POST"])
@login_required
def delete_document(document_id):
    document, permission = require_document_permission(document_id, "edit")
    if permission != "owner":
        audit_attempt("document.delete", "denied", document_id, detail={"reason": "owner_only"})
        abort(403)
    # Soft delete makes the document unavailable immediately while preserving audit evidence.
    with connect_db() as db:
        db.execute("UPDATE documents SET deleted_at=?, updated_at=? WHERE id=?",
                   (utc_now(), utc_now(), document_id))
        db.execute("DELETE FROM grants WHERE document_id=?", (document_id,))
    append_audit("document.delete", document_id=document_id,
                 detail={"title": document["title"], "mode": "soft_delete"})
    flash("Document deleted from active view. Audit record retained.", "success")
    return redirect(url_for("dashboard"))


@app.route("/documents/<int:document_id>/permissions")
@login_required
def permissions(document_id):
    document, permission = require_document_permission(document_id, "read")
    if permission != "owner":
        audit_attempt("permission.list", "denied", document_id, detail={"reason": "owner_only"})
        abort(403)
    with connect_db() as db:
        grants = db.execute("""
            SELECT gr.*, u.name, u.email, u.role FROM grants gr
            JOIN users u ON u.id=gr.user_id WHERE gr.document_id=? ORDER BY u.email
        """, (document_id,)).fetchall()
    return render_template("permissions.html", document=document, grants=grants)


@app.route("/documents/<int:document_id>/permissions", methods=["POST"])
@login_required
def grant_permission(document_id):
    document, permission = require_document_permission(document_id, "read")
    if permission != "owner":
        audit_attempt("permission.grant", "denied", document_id, detail={"reason": "owner_only"})
        abort(403)
    email = request.form.get("email", "").strip().lower()
    level = request.form.get("permission", "read")
    if level not in ("read", "edit"):
        level = "read"
    with connect_db() as db:
        target = db.execute("SELECT id,role,active FROM users WHERE email=?", (email,)).fetchone()
        if not target or not target["active"]:
            append_audit("permission.grant", "denied", document_id=document_id,
                         detail={"email": email, "reason": "recipient_not_found_or_inactive"})
            flash("No active registered user has that email.", "error")
            return redirect(url_for("permissions", document_id=document_id))
        if target["id"] == g.user["id"]:
            flash("You already own this document.", "info")
            return redirect(url_for("permissions", document_id=document_id))
        if target["role"] == "admin":
            flash("Administrative accounts cannot be added as document recipients.", "error")
            return redirect(url_for("permissions", document_id=document_id))
        old = db.execute("SELECT permission FROM grants WHERE document_id=? AND user_id=?",
                         (document_id, target["id"])).fetchone()
        db.execute("""
          INSERT INTO grants(document_id,user_id,permission,granted_by,created_at)
          VALUES(?,?,?,?,?)
          ON CONFLICT(document_id,user_id) DO UPDATE SET permission=excluded.permission,
          granted_by=excluded.granted_by, created_at=excluded.created_at
        """, (document_id, target["id"], level, g.user["id"], utc_now()))
    append_audit("permission.grant" if not old else "permission.change",
                 document_id=document_id, target_user_id=target["id"],
                 detail={"recipient_email": email, "old_permission": old["permission"] if old else None,
                         "new_permission": level})
    flash(f"{level.title()} access granted to {email}.", "success")
    return redirect(url_for("permissions", document_id=document_id))


@app.route("/documents/<int:document_id>/permissions/<int:target_user_id>/revoke", methods=["POST"])
@login_required
def revoke_permission(document_id, target_user_id):
    document, permission = require_document_permission(document_id, "read")
    if permission != "owner":
        audit_attempt("permission.revoke", "denied", document_id, target_user_id,
                      {"reason": "owner_only"})
        abort(403)
    with connect_db() as db:
        existing = db.execute(
            "SELECT permission FROM grants WHERE document_id=? AND user_id=?",
            (document_id, target_user_id)
        ).fetchone()
        if existing:
            db.execute("DELETE FROM grants WHERE document_id=? AND user_id=?",
                       (document_id, target_user_id))
    append_audit("permission.revoke", "success" if existing else "no_op",
                 document_id=document_id, target_user_id=target_user_id,
                 detail={"previous_permission": existing["permission"] if existing else None})
    flash("Access revoked. Future requests are checked against current permissions.", "success")
    return redirect(url_for("permissions", document_id=document_id))


@app.route("/admin/audit")
@roles_required("admin")
def admin_audit():
    with connect_db() as db:
        events = db.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT 500").fetchall()
    return render_template("admin_audit.html", events=events)


@app.route("/admin/audit/verify")
@roles_required("admin")
def verify_audit():
    with connect_db() as db:
        events = db.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
    previous = "GENESIS"
    errors = []
    for event in events:
        payload = {
            "happened_at": event["happened_at"], "actor_id": event["actor_id"],
            "actor_email": event["actor_email"], "action": event["action"],
            "document_id": event["document_id"], "target_user_id": event["target_user_id"],
            "outcome": event["outcome"], "detail_json": event["detail_json"],
            "previous_hash": event["previous_hash"],
        }
        expected = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if event["previous_hash"] != previous or event["event_hash"] != expected:
            errors.append(event["id"])
        previous = event["event_hash"]
    append_audit("audit.verify", detail={"checked_events": len(events), "invalid_event_ids": errors})
    return render_template("audit_verify.html", total=len(events), errors=errors)


@app.route("/admin/users")
@roles_required("admin")
def admin_users():
    with connect_db() as db:
        users = db.execute("SELECT id,name,email,role,active,created_at FROM users ORDER BY id").fetchall()
    return render_template("admin_users.html", users=users)


# ------------------------------- JSON API ---------------------------------
# API uses the same authenticated session and authorization checks as the UI.
# Unsafe requests must include X-CSRFToken from GET /api/v1/csrf.
def api_failure(message, status):
    return jsonify({"error": message, "status": status}), status


def api_login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            audit_attempt("api.auth", "denied", detail={"path": request.path, "reason": "not_authenticated"})
            return api_failure("Authentication required. Log in through the web interface first.", 401)
        return view(*args, **kwargs)
    return wrapped


def api_document_payload(document, permission=None, owner_name=None):
    payload = {
        "id": document["id"], "title": document["title"],
        "category": document["category"], "filename": document["original_name"],
        "size_bytes": document["size_bytes"], "sha256": document["sha256"],
        "created_at": document["created_at"], "updated_at": document["updated_at"],
        "download_url": url_for("api_download_document", document_id=document["id"]),
        "permissions_url": url_for("api_document_permissions", document_id=document["id"]),
    }
    if permission is not None:
        payload["permission"] = permission
    if owner_name is not None:
        payload["owner"] = owner_name
    return payload


@app.get("/api/v1/csrf")
def api_csrf():
    """Return a CSRF token for same-origin browser/API requests."""
    return jsonify({"csrf_token": generate_csrf(), "note": "Send this as X-CSRFToken on POST, PATCH, and DELETE requests."})


@app.get("/api/v1/me")
@api_login_required
def api_me():
    return jsonify({"id": g.user["id"], "name": g.user["name"], "email": g.user["email"], "role": g.user["role"]})


@app.route("/api/v1/documents", methods=["GET", "POST"])
@api_login_required
def api_documents():
    if request.method == "GET":
        query = request.args.get("q", "").strip()[:100]
        category = request.args.get("category", "").strip()[:80]
        sql = """SELECT DISTINCT d.*, u.name AS owner_name, gr.permission AS grant_permission
                 FROM documents d JOIN users u ON u.id=d.owner_id
                 LEFT JOIN grants gr ON gr.document_id=d.id AND gr.user_id=?
                 WHERE d.deleted_at IS NULL AND (d.owner_id=? OR gr.user_id=?)"""
        params = [g.user["id"], g.user["id"], g.user["id"]]
        if query:
            sql += " AND (d.title LIKE ? OR d.original_name LIKE ?)"
            params.extend([f"%{query}%", f"%{query}%"])
        if category:
            sql += " AND d.category LIKE ?"
            params.append(f"%{category}%")
        sql += " ORDER BY d.updated_at DESC"
        with connect_db() as db:
            rows = db.execute(sql, params).fetchall()
        items = []
        for row in rows:
            permission = "owner" if row["owner_id"] == g.user["id"] else row["grant_permission"]
            items.append(api_document_payload(row, permission, row["owner_name"]))
        return jsonify({"items": items, "count": len(items)})

    if g.user["role"] not in ("owner", "admin"):
        audit_attempt("api.document.upload", "denied", detail={"reason": "role_not_allowed"})
        return api_failure("Only owners and admins can upload documents", 403)
    file = request.files.get("document")
    if not file or not file.filename:
        audit_attempt("api.document.upload", "denied", detail={"reason": "missing_file"})
        return api_failure("A document file is required", 400)
    original_name = secure_filename(file.filename)
    if not original_name or not allowed_extension(original_name):
        audit_attempt("api.document.upload", "denied", detail={"filename": original_name, "reason": "extension"})
        return api_failure("File type is not allowed", 400)
    data = file.read(MAX_CONTENT_LENGTH + 1)
    if len(data) > MAX_CONTENT_LENGTH:
        audit_attempt("api.document.upload", "denied", detail={"reason": "size"})
        return api_failure("Maximum upload size is 16 MB", 413)
    if not validate_signature(original_name, data):
        audit_attempt("api.document.upload", "denied", detail={"filename": original_name, "reason": "content_signature"})
        return api_failure("File content does not match its extension or is empty", 400)
    title = request.form.get("title", "").strip()[:160] or original_name
    category = request.form.get("category", "").strip()[:80] or "Uncategorised"
    stored_name = uuid.uuid4().hex
    now = utc_now()
    digest = hashlib.sha256(data).hexdigest()
    try:
        with connect_db() as db:
            cursor = db.execute("""INSERT INTO documents(owner_id,title,category,original_name,stored_name,size_bytes,sha256,file_data,created_at,updated_at)
                                  VALUES(?,?,?,?,?,?,?,?,?,?)""",
                                (g.user["id"], title, category, original_name, stored_name, len(data), digest, sqlite3.Binary(data), now, now))
            doc_id = cursor.lastrowid
        append_audit("document.upload", document_id=doc_id, detail={"title": title, "category": category, "size_bytes": len(data), "sha256": digest, "via": "api"})
    except Exception:
        raise
    with connect_db() as db:
        row = db.execute("SELECT d.*, u.name AS owner_name FROM documents d JOIN users u ON u.id=d.owner_id WHERE d.id=?", (doc_id,)).fetchone()
    return jsonify({"item": api_document_payload(row, "owner", row["owner_name"])}), 201


@app.get("/api/v1/documents/<int:document_id>")
@api_login_required
def api_document_detail(document_id):
    document, permission = require_document_permission(document_id, "read")
    with connect_db() as db:
        owner = db.execute("SELECT name FROM users WHERE id=?", (document["owner_id"],)).fetchone()
    return jsonify({"item": api_document_payload(document, permission, owner["name"] if owner else None)})


@app.get("/api/v1/documents/<int:document_id>/download")
@api_login_required
def api_download_document(document_id):
    document, permission = require_document_permission(document_id, "read")
    if document["file_data"] is None:
        append_audit("document.download", "error", document_id, detail={"reason": "file_missing_or_legacy_file", "via": "api"})
        return api_failure("Document content was not found in the database", 404)
    append_audit("document.download", document_id=document_id, detail={"permission": permission, "sha256": document["sha256"], "via": "api"})
    return send_file(BytesIO(document["file_data"]), as_attachment=True, download_name=document["original_name"])


@app.route("/api/v1/documents/<int:document_id>", methods=["PATCH", "DELETE"])
@api_login_required
def api_document_mutate(document_id):
    document, permission = require_document_permission(document_id, "edit")
    if request.method == "PATCH":
        body = request.get_json(silent=True) or {}
        title = str(body.get("title", document["title"])).strip()[:160]
        category = str(body.get("category", document["category"])).strip()[:80]
        if not title or not category:
            return api_failure("Title and category cannot be empty", 400)
        with connect_db() as db:
            db.execute("UPDATE documents SET title=?,category=?,updated_at=? WHERE id=?", (title, category, utc_now(), document_id))
            row = db.execute("SELECT d.*,u.name AS owner_name FROM documents d JOIN users u ON u.id=d.owner_id WHERE d.id=?", (document_id,)).fetchone()
        append_audit("document.edit", document_id=document_id, detail={"old_title": document["title"], "new_title": title, "old_category": document["category"], "new_category": category, "via": "api"})
        return jsonify({"item": api_document_payload(row, permission, row["owner_name"])})
    if permission != "owner":
        audit_attempt("document.delete", "denied", document_id, detail={"reason": "owner_only", "via": "api"})
        return api_failure("Only the document owner can delete it", 403)
    with connect_db() as db:
        db.execute("UPDATE documents SET deleted_at=?,updated_at=? WHERE id=?", (utc_now(), utc_now(), document_id))
        db.execute("DELETE FROM grants WHERE document_id=?", (document_id,))
    append_audit("document.delete", document_id=document_id, detail={"title": document["title"], "mode": "soft_delete", "via": "api"})
    return jsonify({"message": "Document deleted"})


@app.route("/api/v1/documents/<int:document_id>/permissions", methods=["GET", "POST"])
@api_login_required
def api_document_permissions(document_id):
    document, permission = require_document_permission(document_id, "read")
    if permission != "owner":
        audit_attempt("permission.api", "denied", document_id, detail={"reason": "owner_only"})
        return api_failure("Only the document owner can manage permissions", 403)
    if request.method == "GET":
        with connect_db() as db:
            grants = db.execute("SELECT gr.user_id,u.name,u.email,gr.permission,gr.created_at FROM grants gr JOIN users u ON u.id=gr.user_id WHERE gr.document_id=? ORDER BY u.email", (document_id,)).fetchall()
        return jsonify({"items": [dict(row) for row in grants], "count": len(grants)})
    body = request.get_json(silent=True) or request.form
    email = str(body.get("email", "")).strip().lower()
    level = str(body.get("permission", "read")).strip().lower()
    if level not in ("read", "edit") or not email:
        return api_failure("Provide a registered email and permission 'read' or 'edit'", 400)
    with connect_db() as db:
        target = db.execute("SELECT id,role,active FROM users WHERE email=?", (email,)).fetchone()
        if not target or not target["active"] or target["role"] == "admin" or target["id"] == g.user["id"]:
            append_audit("permission.grant", "denied", document_id, detail={"email": email, "reason": "recipient_invalid", "via": "api"})
            return api_failure("Recipient must be another active non-admin TrustVault user", 400)
        old = db.execute("SELECT permission FROM grants WHERE document_id=? AND user_id=?", (document_id, target["id"])).fetchone()
        db.execute("""INSERT INTO grants(document_id,user_id,permission,granted_by,created_at) VALUES(?,?,?,?,?)
                      ON CONFLICT(document_id,user_id) DO UPDATE SET permission=excluded.permission,granted_by=excluded.granted_by,created_at=excluded.created_at""",
                   (document_id, target["id"], level, g.user["id"], utc_now()))
    append_audit("permission.grant" if not old else "permission.change", document_id=document_id, target_user_id=target["id"], detail={"recipient_email": email, "old_permission": old["permission"] if old else None, "new_permission": level, "via": "api"})
    return jsonify({"message": f"{level.title()} access granted", "user_id": target["id"], "email": email, "permission": level}), 201


@app.delete("/api/v1/documents/<int:document_id>/permissions/<int:target_user_id>")
@api_login_required
def api_revoke_permission(document_id, target_user_id):
    document, permission = require_document_permission(document_id, "read")
    if permission != "owner":
        audit_attempt("permission.revoke", "denied", document_id, target_user_id, {"reason": "owner_only", "via": "api"})
        return api_failure("Only the document owner can revoke access", 403)
    with connect_db() as db:
        existing = db.execute("SELECT permission FROM grants WHERE document_id=? AND user_id=?", (document_id, target_user_id)).fetchone()
        if existing:
            db.execute("DELETE FROM grants WHERE document_id=? AND user_id=?", (document_id, target_user_id))
    append_audit("permission.revoke", "success" if existing else "no_op", document_id=document_id, target_user_id=target_user_id, detail={"via": "api"})
    return jsonify({"message": "Access revoked" if existing else "No active grant existed"})


@app.get("/api/v1/admin/audit")
@api_login_required
def api_admin_audit():
    if g.user["role"] != "admin":
        audit_attempt("api.role.denied", "denied", detail={"path": request.path, "required_role": "admin"})
        return api_failure("Administrator role required", 403)
    with connect_db() as db:
        rows = db.execute("SELECT id,happened_at,actor_id,actor_email,action,document_id,target_user_id,outcome,detail_json,previous_hash,event_hash FROM audit_events ORDER BY id DESC LIMIT 500").fetchall()
    return jsonify({"items": [dict(row) for row in rows], "count": len(rows)})


@app.get("/api/v1/admin/users")
@api_login_required
def api_admin_users():
    if g.user["role"] != "admin":
        audit_attempt("api.role.denied", "denied", detail={"path": request.path, "required_role": "admin"})
        return api_failure("Administrator role required", 403)
    with connect_db() as db:
        rows = db.execute("SELECT id,name,email,role,active,created_at FROM users ORDER BY id").fetchall()
    return jsonify({"items": [dict(row) for row in rows], "count": len(rows)})


@app.get("/api")
def api_explorer():
    return render_template("api_explorer.html")


@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403, message="You are not allowed to perform this action."), 403


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="This resource was not found or you do not have access."), 404


@app.errorhandler(413)
def too_large(_error):
    flash("Maximum upload size is 16 MB.", "error")
    return redirect(url_for("dashboard"))


init_db()

if __name__ == "__main__":
    # Development only. Use a production WSGI server for deployment.
    app.run(debug=True)
