#!/usr/bin/env python3
"""Build an offline DuetOS Wi-Fi firmware kit from a local firmware tree.

The installer cannot assume Wi-Fi works before firmware exists, so this tool
creates a USB/ISO-friendly kit that can be copied to install media. Payloads are
not modified: every firmware file is wrapped in a DUETFWPK envelope with a
SHA-256 digest, provenance metadata, and source-policy flags. At install time the
kernel firmware loader unwraps the package and gives drivers the original bytes.

Input examples:
  --source /lib/firmware
  --source ./linux-firmware

Output layout:
  <out>/manifest.json
  <out>/README.txt
  <out>/licenses/<license files>
  <out>/lib/firmware/<vendor>/<firmware basename>.duetfw
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import importlib.util
import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
MKDUETFW_PATH = REPO_ROOT / "tools" / "firmware" / "mkduetfw.py"


@dataclass(frozen=True)
class FamilySpec:
    key: str
    vendor: str
    family_arg: str
    source_kind: str
    short_name: str
    upstream: str
    patterns: tuple[str, ...]
    license_candidates: tuple[str, ...]
    source_rebuildable: bool
    may_bundle: bool
    regulatory_locked: bool
    redistributable_binary: bool


FAMILIES: tuple[FamilySpec, ...] = (
    FamilySpec(
        key="intel-iwlwifi",
        vendor="intel-iwlwifi",
        family_arg="intel-iwlwifi",
        source_kind="redistributable-binary",
        short_name="iwlwifi",
        upstream="linux-firmware iwlwifi-*.ucode / *.pnvm",
        patterns=("iwlwifi-*.ucode", "iwlwifi-*.pnvm"),
        license_candidates=("LICENCE.iwlwifi_firmware", "LICENSE.iwlwifi_firmware"),
        source_rebuildable=False,
        may_bundle=False,
        regulatory_locked=True,
        redistributable_binary=True,
    ),
    FamilySpec(
        key="realtek-rtl88xx",
        vendor="realtek-rtl88xx",
        family_arg="realtek-rtl88xx",
        source_kind="redistributable-binary",
        short_name="rtl88xx",
        upstream="linux-firmware realtek/rtlwifi, rtw88, and rtw89 blobs",
        patterns=("rtlwifi/*.bin", "rtw88/*.bin", "rtw89/*.bin", "realtek/rtlwifi/*.bin"),
        license_candidates=("LICENCE.rtlwifi_firmware.txt", "LICENCE.rtlwifi_firmware"),
        source_rebuildable=False,
        may_bundle=False,
        regulatory_locked=True,
        redistributable_binary=True,
    ),
    FamilySpec(
        key="ath9k-htc",
        vendor="ath9k-htc",
        family_arg="ath9k-htc",
        source_kind="open-source",
        short_name="ath9k-htc-open",
        upstream="qca/open-ath9k-htc-firmware",
        patterns=("htc_9271.fw", "htc_7010.fw", "ath9k_htc/htc_9271.fw", "ath9k_htc/htc_7010.fw"),
        license_candidates=("LICENCE.open-ath9k-htc-firmware", "LICENSE", "COPYING"),
        source_rebuildable=True,
        may_bundle=True,
        regulatory_locked=True,
        redistributable_binary=False,
    ),
)


def load_mkduetfw_module():
    spec = importlib.util.spec_from_file_location("mkduetfw", MKDUETFW_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {MKDUETFW_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def selected_families(value: str) -> list[FamilySpec]:
    wanted = {item.strip() for item in value.split(",") if item.strip()}
    known = {family.key for family in FAMILIES}
    unknown = sorted(wanted - known)
    if unknown:
        raise ValueError(f"unknown family/families: {', '.join(unknown)}; known: {', '.join(sorted(known))}")
    return [family for family in FAMILIES if family.key in wanted]


def iter_matches(source: Path, patterns: Iterable[str]) -> list[Path]:
    matches: set[Path] = set()
    for pattern in patterns:
        for path in source.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(source).as_posix()
            if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(path.name, pattern):
                matches.add(path)
    return sorted(matches, key=lambda p: p.relative_to(source).as_posix())


def find_license(source: Path, family: FamilySpec) -> Path | None:
    for name in family.license_candidates:
        direct = source / name
        if direct.is_file():
            return direct
    lower_candidates = {name.lower() for name in family.license_candidates}
    for path in source.rglob("*"):
        if path.is_file() and path.name.lower() in lower_candidates:
            return path
    return None


def build_package(mkduetfw, family: FamilySpec, payload: bytes, build_id: int) -> bytes:
    ns = argparse.Namespace(
        family=family.family_arg,
        source_kind=family.source_kind,
        source_rebuildable=family.source_rebuildable,
        may_bundle=family.may_bundle,
        regulatory_locked=family.regulatory_locked,
        custom_lab_image=False,
        allow_lab_image=False,
        short_name=family.short_name,
        upstream=family.upstream,
        build_id=build_id,
    )
    return mkduetfw.build_package(ns, payload)


def write_readme(output: Path, entries: list[dict[str, object]], missing: list[dict[str, str]]) -> None:
    lines = [
        "DuetOS offline Wi-Fi firmware kit",
        "==================================",
        "",
        "Copy this directory onto the installer USB or include it at the root of",
        "release media. The installer should stage lib/firmware into the target",
        "system before starting Wi-Fi setup, then show any licenses listed in",
        "manifest.json before enabling redistributable binary firmware.",
        "",
        f"Packaged firmware files: {len(entries)}",
    ]
    if missing:
        lines.extend(["", "Missing requested families:"])
        for item in missing:
            lines.append(f"- {item['family']}: {item['reason']}")
    lines.extend(
        [
            "",
            "Security/compliance notes:",
            "- Vendor payload bytes are wrapped, not modified.",
            "- SHA-256 in DUETFWPK/manifest pins exact payload bytes.",
            "- Closed firmware must remain an installer/release artifact, not source tree content.",
            "- This kit is not a firmware signing-chain bypass.",
            "",
        ]
    )
    (output / "README.txt").write_text("\n".join(lines), encoding="utf-8")


def create_kit(args: argparse.Namespace) -> int:
    source = args.source.resolve()
    output = args.output.resolve()
    if not source.is_dir():
        raise ValueError(f"source firmware tree does not exist: {source}")
    families = selected_families(args.families)
    mkduetfw = load_mkduetfw_module()

    if output.exists() and args.clean:
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "lib" / "firmware").mkdir(parents=True, exist_ok=True)
    (output / "licenses").mkdir(parents=True, exist_ok=True)

    entries: list[dict[str, object]] = []
    missing: list[dict[str, str]] = []
    license_map: dict[str, str] = {}

    for family in families:
        matches = iter_matches(source, family.patterns)
        license_path = find_license(source, family)
        if family.redistributable_binary and license_path is None and not args.allow_missing_license:
            missing.append(
                {
                    "family": family.key,
                    "reason": "license file not found; rerun with --allow-missing-license only for local lab media",
                }
            )
            continue
        if not matches:
            missing.append({"family": family.key, "reason": "no firmware files matched known patterns"})
            continue

        license_rel = None
        if license_path is not None:
            license_out = output / "licenses" / f"{family.key}-{license_path.name}"
            shutil.copyfile(license_path, license_out)
            license_rel = license_out.relative_to(output).as_posix()
            license_map[family.key] = license_rel

        for src in matches:
            payload = src.read_bytes()
            if not payload:
                continue
            rel = src.relative_to(source).as_posix()
            basename = Path(rel).name
            package = build_package(mkduetfw, family, payload, args.build_id)
            dest = output / "lib" / "firmware" / family.vendor / f"{basename}.duetfw"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(package)
            entries.append(
                {
                    "family": family.key,
                    "vendor": family.vendor,
                    "source_kind": family.source_kind,
                    "source_path": rel,
                    "install_path": dest.relative_to(output).as_posix(),
                    "driver_basename": basename,
                    "payload_size": len(payload),
                    "payload_sha256": hashlib.sha256(payload).hexdigest(),
                    "package_sha256": hashlib.sha256(package).hexdigest(),
                    "license": license_rel,
                    "source_rebuildable": family.source_rebuildable,
                    "may_bundle_in_tree": family.may_bundle,
                    "redistributable_binary": family.redistributable_binary,
                    "regulatory_locked": family.regulatory_locked,
                }
            )

    manifest = {
        "schema": "duetos.wifi-firmware-kit.v1",
        "build_id": args.build_id,
        "source": str(source),
        "entry_count": len(entries),
        "licenses": license_map,
        "entries": entries,
        "missing": missing,
        "installer_policy": {
            "stage_before_wifi_setup": True,
            "show_license_before_redistributable_binary": True,
            "require_sha256_match": True,
            "allow_custom_lab_image": False,
        },
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_readme(output, entries, missing)

    print(f"wrote {len(entries)} firmware package(s) to {output}")
    if missing:
        print(f"warning: {len(missing)} requested family/families missing; see manifest.json", file=sys.stderr)
    return 0 if entries else 1


def run_self_test() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        src = root / "fw"
        src.mkdir()
        (src / "LICENCE.iwlwifi_firmware").write_text("Intel firmware license placeholder for self-test\n")
        (src / "iwlwifi-test.ucode").write_bytes(b"IWL" + bytes(range(64)))
        out = root / "kit"
        ns = argparse.Namespace(
            source=src,
            output=out,
            families="intel-iwlwifi",
            build_id=0x20260508,
            clean=True,
            allow_missing_license=False,
        )
        rc = create_kit(ns)
        assert rc == 0
        manifest = json.loads((out / "manifest.json").read_text())
        assert manifest["schema"] == "duetos.wifi-firmware-kit.v1"
        assert manifest["entry_count"] == 1
        entry = manifest["entries"][0]
        assert entry["driver_basename"] == "iwlwifi-test.ucode"
        assert entry["redistributable_binary"] is True
        assert (out / entry["install_path"]).is_file()
        assert (out / entry["license"]).is_file()
    print("prepare-wifi-firmware.py self-test pass")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, help="local linux-firmware-style tree, e.g. /lib/firmware")
    parser.add_argument("--output", type=Path, help="output firmware kit directory")
    parser.add_argument(
        "--families",
        default="intel-iwlwifi,realtek-rtl88xx,ath9k-htc",
        help="comma-separated family keys to package",
    )
    parser.add_argument("--build-id", type=lambda x: int(x, 0), default=0)
    parser.add_argument("--clean", action="store_true", help="remove output directory before writing")
    parser.add_argument(
        "--allow-missing-license",
        action="store_true",
        help="local-lab escape hatch; release kits should never use this for redistributable binary firmware",
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return args
    if args.source is None or args.output is None:
        parser.error("--source and --output are required unless --self-test is used")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        run_self_test()
        return 0
    return create_kit(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except ValueError as exc:
        print(f"prepare-wifi-firmware.py: error: {exc}", file=sys.stderr)
        raise SystemExit(2)
