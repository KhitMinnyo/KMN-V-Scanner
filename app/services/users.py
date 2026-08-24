"""Local user storage and password hashing."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from typing import Any

from .. import database


ROLES = {"admin", "operator", "viewer"}
ITERATIONS = 600_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_value, digest_value = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_value.encode())
        expected = base64.urlsafe_b64decode(digest_value.encode())
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iterations))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def valid_role(role: str) -> str:
    role = role.strip().lower()
    if role not in ROLES:
        raise ValueError("Role must be admin, operator, or viewer")
    return role


def bootstrap(username: str, password: str, role: str = "admin") -> None:
    if not username or not password:
        return
    role = valid_role(role)
    existing = get_user(username)
    if not existing:
        create_user(username, password, role)


def create_user(username: str, password: str, role: str) -> dict[str, Any]:
    username = username.strip()
    if not username or len(username) > 64 or any(char.isspace() for char in username):
        raise ValueError("Username must be 1-64 characters without spaces")
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters")
    role = valid_role(role)
    with database.connection() as conn:
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, enabled, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)",
                (username, hash_password(password), role, database.utc_now(), database.utc_now()),
            )
        except Exception as exc:
            if "unique" in str(exc).lower():
                raise ValueError("Username already exists") from exc
            raise
    return get_user(username)  # type: ignore[return-value]


def get_user(username: str) -> dict[str, Any] | None:
    with database.connection() as conn:
        row = conn.execute(
            "SELECT id, username, password_hash, role, enabled, created_at, updated_at FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    return dict(row) if row else None


def get_user_by_id(user_id: int) -> dict[str, Any] | None:
    with database.connection() as conn:
        row = conn.execute(
            "SELECT id, username, password_hash, role, enabled, created_at, updated_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    return dict(row) if row else None


def authenticate(username: str, password: str) -> dict[str, Any] | None:
    user = get_user(username.strip())
    if not user or not user["enabled"] or not verify_password(password, user["password_hash"]):
        return None
    user.pop("password_hash", None)
    return user


def list_users() -> list[dict[str, Any]]:
    with database.connection() as conn:
        rows = conn.execute(
            "SELECT id, username, role, enabled, created_at, updated_at FROM users ORDER BY username"
        ).fetchall()
    return [dict(row) for row in rows]


def update_user(user_id: int, role: str | None = None, enabled: bool | None = None, password: str | None = None) -> bool:
    values: dict[str, Any] = {"updated_at": database.utc_now()}
    if role is not None:
        values["role"] = valid_role(role)
    if enabled is not None:
        values["enabled"] = 1 if enabled else 0
    if password is not None:
        if len(password) < 12:
            raise ValueError("Password must be at least 12 characters")
        values["password_hash"] = hash_password(password)
    assignments = ", ".join(f"{key} = ?" for key in values)
    with database.connection() as conn:
        cursor = conn.execute(f"UPDATE users SET {assignments} WHERE id = ?", (*values.values(), user_id))
    return cursor.rowcount > 0


def delete_user(user_id: int) -> bool:
    with database.connection() as conn:
        cursor = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return cursor.rowcount > 0
