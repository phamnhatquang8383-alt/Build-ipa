import os
import sqlite3
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

import keys_admin
from keys_admin import SevError

ADMIN = "admin-password-123"
SECRET = "s" * 40


class KeysAdminTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Path(self._tmp.name) / "keys.sqlite3"
        self._saved = {k: os.environ.get(k) for k in ("SEV_ADMIN_PASSWORD", "SEV_SECRET", "SEV_KEY")}
        os.environ["SEV_ADMIN_PASSWORD"] = ADMIN
        os.environ["SEV_SECRET"] = SECRET
        keys_admin.init_db(self.db)

    def tearDown(self):
        for name, value in self._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        self._tmp.cleanup()

    def test_issued_key_verifies(self):
        key, key_id, _ = keys_admin.issue_key(self.db, "me", 30)
        self.assertEqual(keys_admin.verify_key(self.db, key), key_id)

    def test_key_format(self):
        key, _, _ = keys_admin.issue_key(self.db, "me", 30)
        self.assertTrue(key.startswith("SEV-"))
        self.assertTrue(all(c.isalnum() or c == "-" for c in key))

    def test_database_stores_no_plaintext_key(self):
        key, _, _ = keys_admin.issue_key(self.db, "me", 30)
        raw_db = self.db.read_bytes()
        self.assertNotIn(key.encode(), raw_db)
        self.assertNotIn(key.replace("-", "").encode(), raw_db)

    def test_tampered_key_is_rejected(self):
        key, _, _ = keys_admin.issue_key(self.db, "me", 30)
        body = key.replace("-", "")
        flipped = ("A" if body[5] != "A" else "B")
        tampered = "SEV-" + body[:5] + flipped + body[6:]
        tampered = "-".join(tampered[4:][i : i + 6] for i in range(0, len(tampered[4:]), 6))
        tampered = "SEV-" + tampered
        with self.assertRaises(SevError):
            keys_admin.verify_key(self.db, tampered)

    def test_wrong_secret_is_rejected(self):
        key, _, _ = keys_admin.issue_key(self.db, "me", 30)
        os.environ["SEV_SECRET"] = "x" * 40
        with self.assertRaisesRegex(SevError, "signature is invalid"):
            keys_admin.verify_key(self.db, key)

    def test_revoked_key_is_rejected(self):
        key, key_id, _ = keys_admin.issue_key(self.db, "me", 30)
        keys_admin.revoke_key(self.db, key_id)
        with self.assertRaisesRegex(SevError, "revoked"):
            keys_admin.verify_key(self.db, key)
        statuses = {item["key_id"]: item["status"] for item in keys_admin.list_keys(self.db)}
        self.assertEqual(statuses[key_id], "revoked")

    def test_expired_key_is_rejected(self):
        key, key_id, _ = keys_admin.issue_key(self.db, "me", 1)
        conn = sqlite3.connect(self.db)
        past = (keys_admin._now() - timedelta(days=1)).isoformat()
        conn.execute("UPDATE keys SET expires_at = ? WHERE key_id = ?", (past, key_id))
        conn.commit()
        conn.close()
        with self.assertRaisesRegex(SevError, "expired"):
            keys_admin.verify_key(self.db, key)

    def test_wrong_admin_password_is_rejected(self):
        os.environ["SEV_ADMIN_PASSWORD"] = "not-the-admin-password"
        with self.assertRaisesRegex(SevError, "admin password is wrong"):
            keys_admin.issue_key(self.db, "me", 30)
        with self.assertRaisesRegex(SevError, "admin password is wrong"):
            keys_admin.list_keys(self.db)

    def test_init_twice_is_refused(self):
        with self.assertRaisesRegex(SevError, "already initialized"):
            keys_admin.init_db(self.db)

    def test_short_secret_is_refused(self):
        os.environ["SEV_SECRET"] = "short"
        with self.assertRaisesRegex(SevError, "SEV_SECRET must be at least"):
            keys_admin.issue_key(self.db, "me", 30)

    def test_revoking_unknown_key_fails(self):
        with self.assertRaisesRegex(SevError, "no active key"):
            keys_admin.revoke_key(self.db, "0000000000000000")

    def test_cli_verify_reads_env_only(self):
        key, _, _ = keys_admin.issue_key(self.db, "me", 30)
        os.environ["SEV_KEY"] = key
        self.assertEqual(keys_admin.main(["--db", str(self.db), "verify"]), 0)
        os.environ.pop("SEV_KEY")
        self.assertEqual(keys_admin.main(["--db", str(self.db), "verify"]), 1)


if __name__ == "__main__":
    unittest.main()
