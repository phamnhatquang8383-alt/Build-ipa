#!/usr/bin/env python3
"""sev keys: admin-managed license keys for the PhamQuang IOS build.

init     Create the database and set the single admin password (from SEV_ADMIN_PASSWORD).
issue    Create a key and print it once. Admin only.
list     List keys with their status. Admin only.
revoke   Revoke a key by its key ID. Admin only.
verify   Check a key string: signature, not revoked, not expired.

Environment:
  SEV_ADMIN_PASSWORD  admin password (at least 12 characters). Required for init and admin commands.
  SEV_SECRET          HMAC signing secret (at least 32 characters). Required for issue and verify.

Keys are "SEV-" followed by base32 groups. The payload is 16 random bytes plus a 10-byte
HMAC-SHA256 tag. The database stores only the key ID (a truncated SHA-256 of the random
bytes), the label, the issue and expiry times, and the revocation time. No key is stored.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

KEY_PREFIX = "SEV-"
RANDOM_BYTES = 16
TAG_BYTES = 10
MIN_ADMIN_PASSWORD = 12
MIN_SECRET = 32
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS admin (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    salt BLOB NOT NULL,
    hash BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS keys (
    key_id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);
"""


class SevError(Exception):
    """A check failed. The message names the problem and never contains secret values."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat()


def _require_env(name: str, minimum: int) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise SevError(f"environment variable {name} is not set")
    if len(value) < minimum:
        raise SevError(f"environment variable {name} must be at least {minimum} characters")
    return value


def _scrypt(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=32,
        maxmem=128 * 1024 * 1024,
    )


def _connect(db: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def _require_admin(conn: sqlite3.Connection) -> None:
    password = _require_env("SEV_ADMIN_PASSWORD", MIN_ADMIN_PASSWORD)
    row = conn.execute("SELECT salt, hash FROM admin WHERE id = 1").fetchone()
    if row is None:
        raise SevError("database is not initialized; run init first")
    if not hmac.compare_digest(_scrypt(password, row["salt"]), row["hash"]):
        raise SevError("admin password is wrong")


def init_db(db: Path) -> None:
    password = _require_env("SEV_ADMIN_PASSWORD", MIN_ADMIN_PASSWORD)
    conn = _connect(db)
    try:
        if conn.execute("SELECT 1 FROM admin WHERE id = 1").fetchone() is not None:
            raise SevError("database is already initialized")
        salt = secrets.token_bytes(16)
        conn.execute("INSERT INTO admin (id, salt, hash) VALUES (1, ?, ?)", (salt, _scrypt(password, salt)))
        conn.commit()
    finally:
        conn.close()


def _encode(raw: bytes) -> str:
    text = base64.b32encode(raw).decode("ascii").rstrip("=")
    groups = [text[i : i + 6] for i in range(0, len(text), 6)]
    return KEY_PREFIX + "-".join(groups)


def _decode(key: str) -> bytes:
    text = key.strip().upper()
    if not text.startswith(KEY_PREFIX):
        raise SevError("key does not start with SEV-")
    body = text[len(KEY_PREFIX) :].replace("-", "")
    padding = "=" * (-len(body) % 8)
    try:
        return base64.b32decode(body + padding)
    except ValueError as exc:
        raise SevError("key is not valid base32") from exc


def _tag(secret: str, raw: bytes) -> bytes:
    return hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).digest()[:TAG_BYTES]


def _key_id(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()[:16]


def issue_key(db: Path, label: str, days: int) -> tuple[str, str, datetime]:
    if not label.strip():
        raise SevError("label must not be empty")
    if not 1 <= days <= 3650:
        raise SevError("days must be between 1 and 3650")
    secret = _require_env("SEV_SECRET", MIN_SECRET)
    conn = _connect(db)
    try:
        _require_admin(conn)
        raw = secrets.token_bytes(RANDOM_BYTES)
        key_id = _key_id(raw)
        issued = _now()
        expires = issued + timedelta(days=days)
        conn.execute(
            "INSERT INTO keys (key_id, label, issued_at, expires_at, revoked_at) VALUES (?, ?, ?, ?, NULL)",
            (key_id, label.strip(), _iso(issued), _iso(expires)),
        )
        conn.commit()
    finally:
        conn.close()
    return _encode(raw + _tag(secret, raw)), key_id, expires


def list_keys(db: Path) -> list[dict]:
    conn = _connect(db)
    try:
        _require_admin(conn)
        rows = conn.execute("SELECT * FROM keys ORDER BY issued_at").fetchall()
    finally:
        conn.close()
    now = _now()
    result = []
    for row in rows:
        expires = datetime.fromisoformat(row["expires_at"])
        if row["revoked_at"]:
            status = "revoked"
        elif expires <= now:
            status = "expired"
        else:
            status = "active"
        result.append({"key_id": row["key_id"], "label": row["label"], "status": status, "expires": row["expires_at"]})
    return result


def revoke_key(db: Path, key_id: str) -> None:
    conn = _connect(db)
    try:
        _require_admin(conn)
        cursor = conn.execute(
            "UPDATE keys SET revoked_at = ? WHERE key_id = ? AND revoked_at IS NULL",
            (_iso(_now()), key_id),
        )
        if cursor.rowcount == 0:
            raise SevError(f"no active key with ID {key_id}")
        conn.commit()
    finally:
        conn.close()


def verify_key(db: Path, key: str) -> str:
    secret = _require_env("SEV_SECRET", MIN_SECRET)
    decoded = _decode(key)
    if len(decoded) != RANDOM_BYTES + TAG_BYTES:
        raise SevError("key has the wrong length")
    raw, tag = decoded[:RANDOM_BYTES], decoded[RANDOM_BYTES:]
    if not hmac.compare_digest(_tag(secret, raw), tag):
        raise SevError("key signature is invalid")
    key_id = _key_id(raw)
    conn = _connect(db)
    try:
        row = conn.execute("SELECT * FROM keys WHERE key_id = ?", (key_id,)).fetchone()
    finally:
        conn.close()
    if row is None:
        raise SevError("key is not registered")
    if row["revoked_at"]:
        raise SevError("key has been revoked")
    if datetime.fromisoformat(row["expires_at"]) <= _now():
        raise SevError("key has expired")
    return key_id


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sev keys", description="admin-managed license keys")
    parser.add_argument("--db", type=Path, default=Path("sev/keys.sqlite3"))
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create the database and admin password")
    p_issue = sub.add_parser("issue", help="issue a key")
    p_issue.add_argument("--label", required=True)
    p_issue.add_argument("--days", type=int, default=365)
    sub.add_parser("list", help="list keys")
    p_revoke = sub.add_parser("revoke", help="revoke a key by ID")
    p_revoke.add_argument("key_id")
    p_verify = sub.add_parser("verify", help="verify a key read from an environment variable")
    p_verify.add_argument("--key-env", default="SEV_KEY", help="name of the environment variable holding the key")

    args = parser.parse_args(argv)
    try:
        if args.cmd == "init":
            init_db(args.db)
            print(f"sev keys: initialized {args.db}")
        elif args.cmd == "issue":
            key, key_id, expires = issue_key(args.db, args.label, args.days)
            print(f"key ID: {key_id}")
            print(f"expires: {expires:%Y-%m-%d} UTC")
            print("key (shown once, store it now):")
            print(key)
        elif args.cmd == "list":
            for item in list_keys(args.db):
                print(f"{item['key_id']}  {item['status']:8}  expires {item['expires']}  {item['label']}")
        elif args.cmd == "revoke":
            revoke_key(args.db, args.key_id)
            print(f"sev keys: revoked {args.key_id}")
        else:
            key = os.environ.get(args.key_env, "")
            if not key:
                raise SevError(f"environment variable {args.key_env} is empty")
            key_id = verify_key(args.db, key)
            print(f"sev keys: valid, key ID {key_id}")
    except SevError as exc:
        print(f"sev keys: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
