
"""Create demo users for local review using environment-provided passwords."""
import os
from app import connect_db, utc_now
from werkzeug.security import generate_password_hash

DEMO_USERS = [
    ("Demo Admin", "admin@trustvault.local", "admin"),
    ("Demo Owner", "owner@trustvault.local", "owner"),
    ("Demo Viewer", "viewer@trustvault.local", "viewer"),
]

with connect_db() as db:
    for name, email, role in DEMO_USERS:
        env_key = "TRUSTVAULT_" + role.upper() + "_PASSWORD"
        password = os.environ.get(env_key)

        if not password:
            raise RuntimeError(
                f"Set the {env_key} environment variable before running seed.py."
            )

        db.execute("""
            INSERT INTO users(name,email,password_hash,role,created_at)
            VALUES(?,?,?,?,?)
            ON CONFLICT(email) DO NOTHING
        """, (name, email, generate_password_hash(password), role, utc_now()))

print("Demo accounts ready (existing accounts were left unchanged).")
print("Admin:  admin@trustvault.local")
print("Owner:  owner@trustvault.local")
print("Viewer: viewer@trustvault.local")
print("Set TRUSTVAULT_ADMIN_PASSWORD, TRUSTVAULT_OWNER_PASSWORD, and")
print("TRUSTVAULT_VIEWER_PASSWORD before running this script.")
