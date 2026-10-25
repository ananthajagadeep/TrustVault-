import os
import tempfile
import pytest

@pytest.fixture
def app(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    upload_dir = tmp_path / "uploads"
    monkeypatch.setenv("TRUSTVAULT_DATABASE", str(db_path))
    monkeypatch.setenv("TRUSTVAULT_UPLOAD_DIR", str(upload_dir))
    # app module is imported after env is set by test module fixture helper.
    import importlib, sys
    if "app" in sys.modules:
        del sys.modules["app"]
    app_module = importlib.import_module("app")
    app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False, SECRET_KEY="test-secret")
    yield app_module.app
