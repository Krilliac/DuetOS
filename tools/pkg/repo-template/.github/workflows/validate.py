#!/usr/bin/env python3
"""Validate every package referenced from repo.toml.

Run from the duetos-packages repo root. Exits non-zero on any
failure; intended for use in `.github/workflows/validate.yml`
but works as a local pre-commit check too.

What it checks per [[packages]] entry:
  - referenced binary_url tarball exists under packages/
  - actual SHA-256 of the tarball matches the manifest `sha256`
  - sibling `<tarball>.sig` exists
  - signature verifies against keys/official.pub (an Ed25519
    public key in PEM form, committed by the repo maintainer)
"""

from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import sys
from pathlib import Path

try:
    import tomllib  # 3.11+
except ImportError:
    try:
        import tomli as tomllib  # fallback for older runners
    except ImportError:
        sys.stderr.write("validate.py: needs python 3.11+ tomllib or python3-tomli\n")
        sys.exit(2)


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
REPO_TOML = REPO_ROOT / "repo.toml"
PACKAGES_DIR = REPO_ROOT / "packages"
KEY_PEM = REPO_ROOT / "keys" / "official.pub"


def fail(msg: str) -> None:
    sys.stderr.write(f"validate: FAIL: {msg}\n")
    raise SystemExit(1)


def verify_ed25519(data_path: Path, sig_path: Path, key_path: Path) -> None:
    """Use openssl to verify a detached Ed25519 signature."""
    rc = subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-verify",
            "-rawin",
            "-pubin",
            "-inkey",
            str(key_path),
            "-sigfile",
            str(sig_path),
            "-in",
            str(data_path),
        ],
        capture_output=True,
    )
    if rc.returncode != 0:
        fail(
            f"signature verification failed for {data_path.name}: "
            f"rc={rc.returncode} stderr={rc.stderr.decode(errors='replace').strip()}"
        )


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fp:
        for chunk in iter(lambda: fp.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    if not REPO_TOML.is_file():
        fail(f"missing {REPO_TOML.relative_to(REPO_ROOT)}")
    if not KEY_PEM.is_file():
        fail(f"missing {KEY_PEM.relative_to(REPO_ROOT)} — commit your Ed25519 public key")

    with open(REPO_TOML, "rb") as fp:
        manifest = tomllib.load(fp)

    if "repo" not in manifest:
        fail("repo.toml: missing top-level [repo] table")
    if "name" not in manifest["repo"]:
        fail("repo.toml: missing [repo].name")
    if "signing_key" not in manifest["repo"]:
        fail("repo.toml: missing [repo].signing_key")

    # Sanity-check that the signing_key in repo.toml matches the
    # public key on disk. We don't *need* this for CI (only the
    # maintainer signs with the matching private key), but a
    # mismatch is almost always a bug worth flagging early.
    if manifest["repo"]["signing_key"].startswith("ed25519:"):
        b64 = manifest["repo"]["signing_key"].split(":", 1)[1]
        raw_from_toml = base64.b64decode(b64 + "==")  # tolerate missing padding
        with open(KEY_PEM, "rb") as fp:
            der = base64.b64decode(
                b"".join(
                    line for line in fp.read().splitlines() if b"-----" not in line
                )
            )
        # Ed25519 SPKI: 12-byte header + 32-byte key.
        if len(der) < 44 or der[-32:] != raw_from_toml:
            fail(
                "repo.toml's [repo].signing_key does not match keys/official.pub — "
                "did you commit the wrong public key?"
            )
    else:
        fail("repo.toml: signing_key must start with 'ed25519:'")

    packages = manifest.get("packages", [])
    if not isinstance(packages, list):
        fail("repo.toml: [[packages]] is malformed")
    print(f"validate: {len(packages)} package(s) to check")

    seen_names = set()
    for idx, pkg in enumerate(packages):
        label = f"[[packages]][{idx}]"
        for field in ("name", "version", "binary_url", "sha256"):
            if not pkg.get(field):
                fail(f"{label}: missing required field '{field}'")
        if pkg["name"] in seen_names:
            fail(f"{label}: duplicate package name '{pkg['name']}'")
        seen_names.add(pkg["name"])

        rel = pkg["binary_url"]
        # Resolve binary_url relative to packages/.
        tar_path = PACKAGES_DIR / rel
        if not tar_path.is_file():
            fail(f"{label}: tarball not found at {tar_path.relative_to(REPO_ROOT)}")
        actual_sha = sha256_of(tar_path)
        if actual_sha.lower() != pkg["sha256"].lower():
            fail(
                f"{label}: SHA-256 mismatch for {tar_path.name}: "
                f"manifest={pkg['sha256']} actual={actual_sha}"
            )
        sig_path = tar_path.with_suffix(tar_path.suffix + ".sig")
        if not sig_path.is_file():
            fail(f"{label}: missing signature file {sig_path.relative_to(REPO_ROOT)}")
        verify_ed25519(tar_path, sig_path, KEY_PEM)
        print(f"  OK: {pkg['name']} {pkg['version']} ({tar_path.name})")

    print("validate: every package OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
