"""Optional local Dashboard Passcode & Multi-User RBAC Manager (PBKDF2-SHA256)."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Any, Literal

from app.db.database import Database


Role = Literal["viewer", "analyst", "admin"]
ROLE_RANK: dict[str, int] = {"viewer": 1, "analyst": 2, "admin": 3}


class LocalAuthManager:
    """Manages optional passcode / multi-user RBAC protection without hardcoded fallbacks."""

    def __init__(self, db: Database, session_ttl_seconds: int = 86400) -> None:
        self.db = db
        self.session_ttl_seconds = session_ttl_seconds
        self.enabled: bool = False
        self._salt_hex: str = ""
        self._hash_hex: str = ""
        # token -> (expires_at, username, role)
        self._sessions: dict[str, tuple[float, str, str]] = {}

    async def load_settings(self) -> None:
        self.enabled = bool(await self.db.get_setting("auth_lock_enabled", False))
        self._salt_hex = str(await self.db.get_setting("auth_salt", "") or "")
        self._hash_hex = str(await self.db.get_setting("auth_hash", "") or "")
        users = await self.db.list_users()
        if self.enabled and (not self._salt_hex or not self._hash_hex) and not users:
            self.enabled = False

    def _hash_passcode(self, passcode: str, salt: bytes) -> str:
        dk = hashlib.pbkdf2_hmac("sha256", passcode.encode("utf-8"), salt, 200_000)
        return dk.hex()

    async def enable_passcode(self, passcode: str) -> dict[str, Any]:
        cleaned = passcode.strip()
        if len(cleaned) < 6:
            raise ValueError("Passcode must be at least 6 characters")
        salt = secrets.token_bytes(16)
        salt_hex = salt.hex()
        hash_hex = self._hash_passcode(cleaned, salt)
        self._salt_hex = salt_hex
        self._hash_hex = hash_hex
        self.enabled = True
        await self.db.set_setting("auth_salt", salt_hex)
        await self.db.set_setting("auth_hash", hash_hex)
        await self.db.set_setting("auth_lock_enabled", True)
        token = self._create_session(username="owner", role="admin")
        return {"enabled": True, "token": token, "role": "admin"}

    async def disable_passcode(self, current_passcode: str) -> dict[str, Any]:
        if not self.verify_passcode(current_passcode):
            raise ValueError("Invalid current passcode")
        self.enabled = False
        self._sessions.clear()
        await self.db.set_setting("auth_lock_enabled", False)
        return {"enabled": False}

    def verify_passcode(self, passcode: str) -> bool:
        if not self._salt_hex or not self._hash_hex:
            return False
        candidate = self._hash_passcode(passcode.strip(), bytes.fromhex(self._salt_hex))
        return hmac.compare_digest(candidate, self._hash_hex)

    def _create_session(self, *, username: str = "owner", role: str = "admin") -> str:
        if len(self._sessions) > 128:
            self._sessions.clear()
        token = secrets.token_urlsafe(32)
        self._sessions[token] = (time.monotonic() + self.session_ttl_seconds, username, role)
        return token

    def login(self, passcode: str) -> str | None:
        if not self.enabled or not self.verify_passcode(passcode):
            return None
        return self._create_session(username="owner", role="admin")

    async def create_user(self, username: str, password: str, role: Role = "viewer") -> dict[str, Any]:
        clean_user = username.strip().lower()
        clean_pw = password.strip()
        if len(clean_user) < 3:
            raise ValueError("Username must be at least 3 characters")
        if len(clean_pw) < 6:
            raise ValueError("Password must be at least 6 characters")
        if role not in ROLE_RANK:
            raise ValueError("Invalid role")
        salt = secrets.token_bytes(16)
        created = await self.db.create_user(
            username=clean_user,
            role=role,
            salt=salt.hex(),
            password_hash=self._hash_passcode(clean_pw, salt),
        )
        if not self.enabled and role == "admin":
            self.enabled = True
            await self.db.set_setting("auth_lock_enabled", True)
        return created

    async def login_user(self, username: str, password: str) -> dict[str, str] | None:
        row = await self.db.get_user_auth(username.strip().lower())
        if row is None:
            return None
        candidate = self._hash_passcode(password.strip(), bytes.fromhex(row["salt"]))
        if not hmac.compare_digest(candidate, row["password_hash"]):
            return None
        token = self._create_session(username=row["username"], role=row["role"])
        return {"token": token, "username": row["username"], "role": row["role"]}

    def get_actor(self, token: str | None) -> dict[str, str] | None:
        if not self.enabled:
            return {"username": "local-admin", "role": "admin"}
        if not token:
            return None
        session = self._sessions.get(token)
        if session is None:
            return None
        exp, username, role = session
        if time.monotonic() > exp:
            del self._sessions[token]
            return None
        return {"username": username, "role": role}

    def is_token_valid(self, token: str | None) -> bool:
        return self.get_actor(token) is not None

    def has_min_role(self, token: str | None, min_role: Role) -> bool:
        actor = self.get_actor(token)
        if actor is None:
            return False
        return ROLE_RANK.get(actor["role"], 0) >= ROLE_RANK.get(min_role, 99)

    def logout(self, token: str | None) -> None:
        if token:
            self._sessions.pop(token, None)
