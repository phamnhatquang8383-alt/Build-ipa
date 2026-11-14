import os
import plistlib
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import sev_keys
from sev_keys import SevError

HAS_OPENSSL = shutil.which("openssl") is not None
HAS_GIT = shutil.which("git") is not None
BUNDLE = "sato.cc365.file"
TEAM = "ABCDE12345"
P12_ENV = "SEV_TEST_P12_PASS"


def _write_ipa(path: Path, *, info: dict, extra: dict[str, bytes] | None = None, signed: bool = True) -> Path:
    files = {"Payload/PhamQuangIOS.app/Info.plist": plistlib.dumps(info)}
    if signed:
        files["Payload/PhamQuangIOS.app/_CodeSignature/CodeResources"] = b"<plist/>"
    files.update(extra or {})
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return path


def _good_info() -> dict:
    return {
        "CFBundleIdentifier": BUNDLE,
        "CFBundleShortVersionString": "1.4.1",
        "CFBundleVersion": "8",
    }


class GuardTests(unittest.TestCase):
    @unittest.skipUnless(HAS_GIT, "git not installed")
    def test_guard_passes_clean_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "-C", tmp, "init", "-q"], check=True)
            (Path(tmp) / "README.md").write_text("ok\n")
            subprocess.run(["git", "-C", tmp, "add", "README.md"], check=True)
            self.assertEqual(sev_keys.guard(Path(tmp)), 1)

    @unittest.skipUnless(HAS_GIT, "git not installed")
    def test_guard_rejects_tracked_p12(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "-C", tmp, "init", "-q"], check=True)
            (Path(tmp) / "dist").mkdir()
            (Path(tmp) / "dist" / "cert.p12").write_bytes(b"x")
            subprocess.run(["git", "-C", tmp, "add", "dist/cert.p12"], check=True)
            with self.assertRaisesRegex(SevError, "cert.p12"):
                sev_keys.guard(Path(tmp))


class VerifyIpaTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_accepts_signed_ipa_with_embedded_profile(self):
        ipa = _write_ipa(
            self.dir / "ok.ipa",
            info=_good_info(),
            extra={"Payload/PhamQuangIOS.app/embedded.mobileprovision": b"profile"},
        )
        self.assertEqual(sev_keys.verify_ipa(ipa, BUNDLE, "1.4.1", "8"), "PhamQuangIOS.app")

    def test_rejects_p12_inside_ipa(self):
        ipa = _write_ipa(self.dir / "bad.ipa", info=_good_info(), extra={"Payload/PhamQuangIOS.app/cert.p12": b"x"})
        with self.assertRaisesRegex(SevError, "signing material"):
            sev_keys.verify_ipa(ipa, BUNDLE, "1.4.1", "8")

    def test_rejects_wrong_bundle_id(self):
        info = _good_info()
        info["CFBundleIdentifier"] = "sato.cc365.other"
        ipa = _write_ipa(self.dir / "wrong.ipa", info=info)
        with self.assertRaisesRegex(SevError, "Info.plist mismatch"):
            sev_keys.verify_ipa(ipa, BUNDLE, "1.4.1", "8")

    def test_rejects_unsigned_when_signature_required(self):
        ipa = _write_ipa(self.dir / "unsigned.ipa", info=_good_info(), signed=False)
        with self.assertRaisesRegex(SevError, "not code signed"):
            sev_keys.verify_ipa(ipa, BUNDLE, "1.4.1", "8")
        self.assertEqual(sev_keys.verify_ipa(ipa, BUNDLE, "1.4.1", "8", allow_unsigned=True), "PhamQuangIOS.app")

    def test_rejects_path_traversal(self):
        ipa = _write_ipa(self.dir / "trav.ipa", info=_good_info(), extra={"Payload/../evil": b"x"})
        with self.assertRaisesRegex(SevError, "unsafe path"):
            sev_keys.verify_ipa(ipa, BUNDLE, "1.4.1", "8")

    def test_rejects_non_zip(self):
        bogus = self.dir / "bogus.ipa"
        bogus.write_bytes(b"not a zip")
        with self.assertRaisesRegex(SevError, "not a zip"):
            sev_keys.verify_ipa(bogus, BUNDLE, "1.4.1", "8")


class TeamRegexTests(unittest.TestCase):
    def test_extracts_team_from_subject(self):
        subject = "subject=UID=x, CN=Apple Distribution: Test, OU=ABCDE12345, O=Test, C=US"
        self.assertEqual(sev_keys.TEAM_ID_RE.search(subject).group(1), TEAM)

    def test_accepts_openssl3_spacing(self):
        subject = "subject=CN = Apple Distribution: Test, OU = ABCDE12345, O = Test, C = US"
        self.assertEqual(sev_keys.TEAM_ID_RE.search(subject).group(1), TEAM)

    def test_ignores_short_ou(self):
        self.assertIsNone(sev_keys.TEAM_ID_RE.search("subject=CN=x, OU=ABC, C=US"))


@unittest.skipUnless(HAS_OPENSSL, "openssl not installed")
class CheckSigningTests(unittest.TestCase):
    """Builds a self-signed identity and a CMS-signed plist standing in for a profile."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.key = self.dir / "key.pem"
        self.cert = self.dir / "cert.pem"
        self.p12 = self.dir / "cert.p12"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-keyout", str(self.key), "-out", str(self.cert),
                "-subj", f"/CN=Apple Distribution: Test/OU={TEAM}/O=Test/C=US",
            ],
            check=True, capture_output=True,
        )
        os.environ[P12_ENV] = "unit-test-pass-123"
        subprocess.run(
            [
                "openssl", "pkcs12", "-export", "-inkey", str(self.key), "-in", str(self.cert),
                "-out", str(self.p12), "-passout", f"env:{P12_ENV}",
            ],
            check=True, capture_output=True,
        )

    def tearDown(self):
        os.environ.pop(P12_ENV, None)
        self._tmp.cleanup()

    def _profile(self, *, app_id: str, team: str = TEAM, expires: datetime | None = None) -> Path:
        cert_der = subprocess.run(
            ["openssl", "x509", "-in", str(self.cert), "-outform", "DER"],
            check=True, capture_output=True,
        ).stdout
        plist = {
            "TeamIdentifier": [team],
            "Entitlements": {"application-identifier": app_id},
            "ExpirationDate": (expires or datetime.now(timezone.utc) + timedelta(days=30)).replace(tzinfo=None),
            "DeveloperCertificates": [cert_der],
        }
        raw = self.dir / "profile.plist"
        raw.write_bytes(plistlib.dumps(plist))
        out = self.dir / "profile.mobileprovision"
        subprocess.run(
            [
                "openssl", "smime", "-sign", "-nodetach", "-binary", "-outform", "DER",
                "-signer", str(self.cert), "-inkey", str(self.key),
                "-in", str(raw), "-out", str(out),
            ],
            check=True, capture_output=True,
        )
        return out

    def test_accepts_matching_identity_and_profile(self):
        profile = self._profile(app_id=f"{TEAM}.{BUNDLE}")
        report = sev_keys.check_signing(self.p12, P12_ENV, profile, BUNDLE)
        self.assertEqual(report.team_id, TEAM)
        self.assertEqual(report.app_id, f"{TEAM}.{BUNDLE}")

    def test_accepts_wildcard_profile(self):
        profile = self._profile(app_id=f"{TEAM}.*")
        self.assertEqual(sev_keys.check_signing(self.p12, P12_ENV, profile, BUNDLE).team_id, TEAM)

    def test_rejects_profile_for_other_bundle(self):
        profile = self._profile(app_id=f"{TEAM}.com.example.other")
        with self.assertRaisesRegex(SevError, "does not cover bundle ID"):
            sev_keys.check_signing(self.p12, P12_ENV, profile, BUNDLE)

    def test_rejects_expired_profile(self):
        profile = self._profile(app_id=f"{TEAM}.{BUNDLE}", expires=datetime.now(timezone.utc) - timedelta(days=1))
        with self.assertRaisesRegex(SevError, "expired"):
            sev_keys.check_signing(self.p12, P12_ENV, profile, BUNDLE)

    def test_rejects_profile_with_other_team(self):
        profile = self._profile(app_id=f"ZZZZZ99999.{BUNDLE}", team="ZZZZZ99999")
        with self.assertRaisesRegex(SevError, "team ID does not match"):
            sev_keys.check_signing(self.p12, P12_ENV, profile, BUNDLE)

    def test_missing_password_env_is_reported_without_value(self):
        profile = self._profile(app_id=f"{TEAM}.{BUNDLE}")
        os.environ.pop(P12_ENV)
        with self.assertRaisesRegex(SevError, f"{P12_ENV} is not set"):
            sev_keys.check_signing(self.p12, P12_ENV, profile, BUNDLE)


if __name__ == "__main__":
    unittest.main()
