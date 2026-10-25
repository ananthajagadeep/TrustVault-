import io
import os
import sys
import importlib
import pytest
from werkzeug.security import generate_password_hash


def seed_user(app, name, email, role, password="Correct-Horse-Battery-1"):
    module = sys.modules["app"]
    with module.connect_db() as db:
        db.execute(
            "INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
            (name, email, generate_password_hash(password), role, module.utc_now())
        )
        return db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]


def login(client, email, password="Correct-Horse-Battery-1"):
    return client.post("/login", data={"email": email, "password": password}, follow_redirects=True)


@pytest.fixture
def users(app):
    admin = seed_user(app, "Admin", "admin@test.local", "admin")
    alice = seed_user(app, "Alice", "alice@test.local", "owner")
    bob = seed_user(app, "Bob", "bob@test.local", "viewer")
    charlie = seed_user(app, "Charlie", "charlie@test.local", "owner")
    return {"admin": admin, "alice": alice, "bob": bob, "charlie": charlie}


def upload_pdf(client, name="report.pdf", title="Report"):
    return client.post("/upload", data={
        "title": title, "category": "Contracts",
        "document": (io.BytesIO(b"%PDF-1.7\\nmock pdf bytes"), name)
    }, content_type="multipart/form-data", follow_redirects=True)


def first_document_id():
    module = sys.modules["app"]
    with module.connect_db() as db:
        return db.execute("SELECT id FROM documents ORDER BY id LIMIT 1").fetchone()["id"]


def test_ungranted_user_cannot_download_document(app, users):
    alice = app.test_client()
    bob = app.test_client()
    login(alice, "alice@test.local")
    upload_pdf(alice)
    doc_id = first_document_id()

    login(bob, "bob@test.local")
    response = bob.get(f"/documents/{doc_id}/download")
    assert response.status_code == 404
    with sys.modules["app"].connect_db() as db:
        denied = db.execute(
            "SELECT 1 FROM audit_events WHERE action='document.access' AND outcome='denied' AND document_id=?",
            (doc_id,)
        ).fetchone()
    assert denied is not None


def test_grant_allows_download_and_revoke_removes_it(app, users):
    alice = app.test_client()
    bob = app.test_client()
    login(alice, "alice@test.local")
    upload_pdf(alice)
    doc_id = first_document_id()

    response = alice.post(f"/documents/{doc_id}/permissions", data={
        "email": "bob@test.local", "permission": "read"
    }, follow_redirects=True)
    assert response.status_code == 200

    login(bob, "bob@test.local")
    assert bob.get(f"/documents/{doc_id}/download").status_code == 200

    # Owner revokes access; subsequent request must fail without logging in again.
    alice.post(f"/documents/{doc_id}/permissions/{users['bob']}/revoke", data={}, follow_redirects=True)
    assert bob.get(f"/documents/{doc_id}/download").status_code == 404


def test_edit_permission_is_required_to_change_metadata(app, users):
    alice = app.test_client()
    bob = app.test_client()
    login(alice, "alice@test.local")
    upload_pdf(alice)
    doc_id = first_document_id()
    alice.post(f"/documents/{doc_id}/permissions", data={
        "email": "bob@test.local", "permission": "read"
    }, follow_redirects=True)
    login(bob, "bob@test.local")
    response = bob.post(f"/documents/{doc_id}/edit", data={
        "title": "Hacked title", "category": "Changed"
    })
    assert response.status_code == 404
    with sys.modules["app"].connect_db() as db:
        title = db.execute("SELECT title FROM documents WHERE id=?", (doc_id,)).fetchone()["title"]
    assert title == "Report"


def test_user_cannot_grant_permission_on_another_owners_document(app, users):
    alice = app.test_client()
    charlie = app.test_client()
    bob = app.test_client()
    login(alice, "alice@test.local")
    upload_pdf(alice)
    doc_id = first_document_id()
    login(charlie, "charlie@test.local")
    response = charlie.post(f"/documents/{doc_id}/permissions", data={
        "email": "bob@test.local", "permission": "edit"
    })
    assert response.status_code in (403, 404)
    login(bob, "bob@test.local")
    assert bob.get(f"/documents/{doc_id}/download").status_code == 404


def test_viewer_cannot_upload(app, users):
    viewer = app.test_client()
    login(viewer, "bob@test.local")
    response = upload_pdf(viewer)
    assert response.status_code == 403
    with sys.modules["app"].connect_db() as db:
        count = db.execute("SELECT COUNT(*) AS n FROM documents").fetchone()["n"]
    assert count == 0


def test_admin_can_view_audit_but_does_not_get_document_content_access(app, users):
    alice = app.test_client()
    admin = app.test_client()
    login(alice, "alice@test.local")
    upload_pdf(alice)
    doc_id = first_document_id()
    login(admin, "admin@test.local")
    assert admin.get("/admin/audit").status_code == 200
    assert admin.get(f"/documents/{doc_id}/download").status_code == 404


def test_invalid_file_signature_is_rejected(app, users):
    alice = app.test_client()
    login(alice, "alice@test.local")
    response = alice.post("/upload", data={
        "title": "Fake PDF", "category": "Test",
        "document": (io.BytesIO(b"this is not a pdf"), "fake.pdf")
    }, content_type="multipart/form-data", follow_redirects=True)
    assert b"File content does not match" in response.data
    with sys.modules["app"].connect_db() as db:
        assert db.execute("SELECT COUNT(*) AS n FROM documents").fetchone()["n"] == 0
