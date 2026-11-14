#!/usr/bin/env python3
"""sev: signing-material checks for the PhamQuangIOS IPA build.

check   Validate the .p12 signing identity against the .mobileprovision profile:
        team ID, bundle ID coverage, expiry, and that the profile lists this certificate.
verify  Validate a packaged IPA: one app bundle, bundle ID and version, no signing
        material other than the embedded profile, and a code signature present.
guard   Fail if signing material is tracked by git in a repository.

The .p12 password is read from an environment variable and never printed. The
profile's CMS signature is not chain-verified (-noverify): the profile is only
read for its fields and its certificate list is compared with the .p12 certificate.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import os
import plistlib
import re
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

TEAM_ID_RE = re.compile(r"\bOU\s*=\s*([A-Z0-9]{10})\b")
CERT_PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)
SIGNING_MATERIAL_PATTERNS = (
    "*.p12",
    "*.pfx",
    "*.mobileprovision",
    "*.provisionprofile",
    "*.keychain",
    "*.keychain-db",
    "*.key",
    "*.pem",
)
EMBEDDED_PROFILE_NAME = "embedded.mobileprovision"


class SevError(Exception):
    """A check failed. The message names the check and never contains secret values."""


@dataclass(frozen=True)
class SigningReport:
    team_id: str
    app_id: str
    expires: datetime
    cert_sha256: str


def _is_signing_material(path: str) -> bool:
    name = Path(path).name.lower()
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in SIGNING_MATERIAL_PATTERNS)


def _run(args: list[str], stdin: bytes | None = None) -> bytes:
    try:
        proc = subprocess.run(args, input=stdin, capture_output=True, check=False)
    except OSError as exc:
        raise SevError(f"cannot run {args[0]}: {exc.strerror}") from exc
    if proc.returncode != 0:
        raise SevError(f"{os.path.basename(args[0])} exited with code {proc.returncode}")
    return proc.stdout


def _x509(pem: bytes, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["openssl", "x509", *args], input=pem, capture_output=True, check=False)


def _x509_output(pem: bytes, *args: str) -> bytes:
    proc = _x509(pem, *args)
    if proc.returncode != 0:
        raise SevError(f"openssl x509 {' '.join(args)} failed with exit code {proc.returncode}")
    return proc.stdout


def check_signing(p12: Path, password_env: str, profile: Path, bundle_id: str) -> SigningReport:
    if password_env not in os.environ:
        raise SevError(f"environment variable {password_env} is not set")

    bundle = _run(
        ["openssl", "pkcs12", "-in", str(p12), "-nokeys", "-clcerts", "-passin", f"env:{password_env}"]
    )
    match = CERT_PEM_RE.search(bundle.decode("ascii", "replace"))
    if match is None:
        raise SevError("no certificate found in the .p12 file")
    pem = match.group(0).encode("ascii") + b"\n"

    subject = _x509_output(pem, "-noout", "-subject").decode("utf-8", "replace")
    team = TEAM_ID_RE.search(subject)
    if team is None:
        raise SevError("signing certificate has no 10-character team ID in its OU field")
    if _x509(pem, "-noout", "-checkend", "0").returncode != 0:
        raise SevError("signing certificate has expired")
    cert_sha256 = hashlib.sha256(_x509_output(pem, "-outform", "DER")).hexdigest()

    profile_plist = plistlib.loads(
        _run(["openssl", "smime", "-verify", "-noverify", "-inform", "DER", "-in", str(profile)])
    )

    team_list = profile_plist.get("TeamIdentifier") or []
    if not team_list or team_list[0] != team.group(1):
        raise SevError("profile team ID does not match the signing certificate team ID")

    app_id = profile_plist.get("Entitlements", {}).get("application-identifier", "")
    if not fnmatch.fnmatchcase(f"{team.group(1)}.{bundle_id}", app_id):
        raise SevError(f"profile application identifier {app_id!r} does not cover bundle ID {bundle_id!r}")

    expires = profile_plist.get("ExpirationDate")
    if not isinstance(expires, datetime):
        raise SevError("profile has no ExpirationDate")
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires <= datetime.now(timezone.utc):
        raise SevError("provisioning profile has expired")

    listed = {hashlib.sha256(bytes(cert)).hexdigest() for cert in profile_plist.get("DeveloperCertificates", [])}
    if cert_sha256 not in listed:
        raise SevError("provisioning profile does not list this signing certificate")

    return SigningReport(team.group(1), app_id, expires, cert_sha256)


def verify_ipa(
    ipa: Path, bundle_id: str, version: str, build: str, *, allow_unsigned: bool = False
) -> str:
    if not ipa.is_file():
        raise SevError(f"IPA not found: {ipa}")
    if not zipfile.is_zipfile(ipa):
        raise SevError("file is not a zip archive")
    with zipfile.ZipFile(ipa) as archive:
        names = archive.namelist()
        for name in names:
            if name.startswith("/") or ".." in name.split("/"):
                raise SevError(f"unsafe path in archive: {name!r}")

        apps = sorted(
            {
                parts[1]
                for parts in (name.split("/") for name in names)
                if len(parts) >= 3 and parts[0] == "Payload" and parts[1].endswith(".app")
            }
        )
        if len(apps) != 1:
            raise SevError(f"expected exactly one .app in Payload, found {len(apps)}")
        app_dir = f"Payload/{apps[0]}"

        embedded = f"{app_dir}/{EMBEDDED_PROFILE_NAME}"
        for name in names:
            if name != embedded and _is_signing_material(name):
                raise SevError(f"signing material inside the IPA: {name}")

        if not allow_unsigned and f"{app_dir}/_CodeSignature/CodeResources" not in names:
            raise SevError("app bundle is not code signed")

        info = plistlib.loads(archive.read(f"{app_dir}/Info.plist"))

    expected = (bundle_id, version, build)
    actual = (
        info.get("CFBundleIdentifier"),
        info.get("CFBundleShortVersionString"),
        info.get("CFBundleVersion"),
    )
    if actual != expected:
        raise SevError(f"Info.plist mismatch: expected {expected}, got {actual}")
    return apps[0]


def guard(repo: Path) -> int:
    listing = _run(["git", "-C", str(repo), "ls-files", "-z"]).decode("utf-8", "replace")
    tracked = [path for path in listing.split("\0") if path]
    hits = [path for path in tracked if _is_signing_material(path)]
    if hits:
        raise SevError("signing material is tracked by git: " + ", ".join(hits))
    return len(tracked)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sev", description=__doc__.splitlines()[0] if __doc__ else "sev")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_check = sub.add_parser("check", help="validate .p12 identity against the profile")
    p_check.add_argument("--p12", type=Path, required=True)
    p_check.add_argument("--password-env", default="IOS_P12_PASSWORD")
    p_check.add_argument("--profile", type=Path, required=True)
    p_check.add_argument("--bundle-id", required=True)

    p_verify = sub.add_parser("verify", help="validate a packaged IPA")
    p_verify.add_argument("--ipa", type=Path, required=True)
    p_verify.add_argument("--bundle-id", required=True)
    p_verify.add_argument("--version", required=True)
    p_verify.add_argument("--build", required=True)
    p_verify.add_argument("--allow-unsigned", action="store_true")

    p_guard = sub.add_parser("guard", help="fail if signing material is tracked by git")
    p_guard.add_argument("--repo", type=Path, default=Path("."))

    args = parser.parse_args(argv)
    try:
        if args.cmd == "check":
            report = check_signing(args.p12, args.password_env, args.profile, args.bundle_id)
            print(
                f"sev check ok: team {report.team_id}, application identifier {report.app_id}, "
                f"profile expires {report.expires:%Y-%m-%d} UTC, certificate sha256 {report.cert_sha256[:16]}"
            )
        elif args.cmd == "verify":
            app = verify_ipa(
                args.ipa, args.bundle_id, args.version, args.build, allow_unsigned=args.allow_unsigned
            )
            print(f"sev verify ok: {app} is {args.bundle_id} {args.version} ({args.build})")
        else:
            count = guard(args.repo)
            print(f"sev guard ok: {count} tracked files, no signing material")
    except SevError as exc:
        print(f"sev: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
