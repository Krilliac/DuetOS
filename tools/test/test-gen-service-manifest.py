#!/usr/bin/env python3
"""Hostile and determinism tests for gen-service-manifest.py."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
GENERATOR_PATH = REPO_ROOT / "tools" / "build" / "gen-service-manifest.py"
CONFIG_PATH = REPO_ROOT / "config" / "services.toml"
HEADER_PATH = REPO_ROOT / "kernel" / "core" / "boot_service_manifest_data.h"
AUTHORITY_PATH = REPO_ROOT / "config" / "service-authority.toml"

SPEC = importlib.util.spec_from_file_location("duetos_gen_service_manifest", GENERATOR_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot import {GENERATOR_PATH}")
GENERATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GENERATOR
SPEC.loader.exec_module(GENERATOR)


BASE_MANIFEST = textwrap.dedent(
    """\
    [manifest]
    format_version = 1
    manifest_identity = 0x100
    signer_identity = 0x200
    profile_identity = 0x300
    artifacts_resolved = false

    [[service]]
    identity = 0x10
    name = "alpha"
    path = "/system/alpha"
    transfer_ref = 1
    staged_content_label = "services/alpha/v1"
    immutable_policy_selector = 1
    kind = "broker"
    restart = "always"
    autostart = true
    resource_profile = "authenticated-service"
    capabilities = ["fs-read", "spawn-thread"]
    frame_budget_pages = 128
    tick_budget = 10000
    section_objects = 2
    section_pages = 64
    dependencies = []

    [[service]]
    identity = 0x20
    name = "beta"
    path = "/system/beta"
    transfer_ref = 2
    staged_content_label = "services/beta/v1"
    immutable_policy_selector = 1
    kind = "native"
    restart = "on-failure"
    autostart = true
    resource_profile = "authenticated-service"
    capabilities = ["serial-console"]
    frame_budget_pages = 256
    tick_budget = 20000
    section_objects = 3
    section_pages = 128
    dependencies = ["alpha"]
    """
)


class ManifestGeneratorTest(unittest.TestCase):
    def _load_text(self, text: str):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "services.toml"
            path.write_text(text, encoding="utf-8", newline="\n")
            return GENERATOR.load_manifest(path)

    def _assert_rejected(self, text: str, contains: str | None = None) -> None:
        with self.assertRaises(GENERATOR.ManifestError) as caught:
            self._load_text(text)
        if contains is not None:
            self.assertIn(contains, str(caught.exception))

    def test_checked_in_header_is_exact_and_check_mode_is_clean(self) -> None:
        manifest = GENERATOR.load_manifest(CONFIG_PATH)
        wire = GENERATOR.encode_manifest(manifest)
        expected = GENERATOR.render_header(manifest, wire, "config/services.toml")
        self.assertEqual(HEADER_PATH.read_text(encoding="ascii"), expected)
        self.assertFalse(manifest.artifacts_resolved)
        self.assertTrue(all(service.content_source.startswith("staged:") for service in manifest.services))
        self.assertIn("kBootServiceManifestArtifactsResolved = false", expected)
        self.assertIn("kBootServiceManifestActivationReady = false", expected)
        serviced = next(service for service in manifest.services if service.name == "serviced")
        self.assertNotEqual(serviced.capability_mask & (1 << GENERATOR.CAPABILITY_BITS["service-control"]), 0)
        for service in manifest.services:
            if service.name != "serviced":
                self.assertEqual(service.capability_mask & (1 << GENERATOR.CAPABILITY_BITS["service-control"]), 0)

        result = subprocess.run(
            [
                sys.executable,
                str(GENERATOR_PATH),
                "--input",
                str(CONFIG_PATH),
                "--header",
                str(HEADER_PATH),
                "--check",
            ],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(hashlib.sha256(wire).hexdigest(), result.stdout)

    def test_wire_matches_production_layout_and_dependency_contract(self) -> None:
        manifest = GENERATOR.load_manifest(CONFIG_PATH)
        wire = GENERATOR.encode_manifest(manifest)
        header = struct.unpack_from("<IHHHHHHIIQQQIIQ", wire, 0)
        (
            total_size,
            version,
            header_bytes,
            service_bytes,
            dependency_bytes,
            service_count,
            dependency_count,
            flags,
            reserved32,
            manifest_identity,
            signer_identity,
            profile_identity,
            services_offset,
            dependencies_offset,
            reserved64,
        ) = header
        self.assertEqual(total_size, len(wire))
        self.assertEqual((version, header_bytes, service_bytes, dependency_bytes), (1, 64, 256, 16))
        self.assertEqual((service_count, dependency_count), (5, 4))
        self.assertEqual(total_size, 1408)
        self.assertEqual((flags, reserved32, reserved64), (0, 0, 0))
        self.assertEqual(manifest_identity, manifest.manifest_identity)
        self.assertEqual(signer_identity, manifest.signer_identity)
        self.assertEqual(profile_identity, manifest.profile_identity)
        self.assertEqual(services_offset, 64)
        self.assertEqual(dependencies_offset, 64 + service_count * 256)

        dependency_cursor = 0
        for index, service in enumerate(manifest.services):
            row = services_offset + index * service_bytes
            identity, transfer_ref, policy = struct.unpack_from("<QII", wire, row)
            dep_first, dep_count = struct.unpack_from("<HH", wire, row + 80)
            name_length, path_length, kind, restart, autostart, profile = struct.unpack_from(
                "<BBBBBB", wire, row + 84
            )
            self.assertEqual(identity, service.identity)
            self.assertEqual(transfer_ref, service.transfer_ref)
            self.assertEqual(policy, service.immutable_policy_selector)
            self.assertEqual(wire[row + 16 : row + 48], service.content_hash)
            self.assertEqual((dep_first, dep_count), (dependency_cursor, len(service.dependency_identities)))
            self.assertEqual(wire[row + 96 : row + 96 + name_length].decode("ascii"), service.name)
            self.assertEqual(wire[row + 128 : row + 128 + path_length].decode("ascii"), service.path)
            self.assertEqual(kind, GENERATOR.KIND_VALUES[service.kind])
            self.assertEqual(restart, GENERATOR.RESTART_VALUES[service.restart])
            self.assertEqual(autostart, int(service.autostart))
            self.assertEqual(profile, GENERATOR.RESOURCE_VALUES[service.resource_profile])
            for dependency in service.dependency_identities:
                edge = dependencies_offset + dependency_cursor * dependency_bytes
                self.assertEqual(struct.unpack_from("<QQ", wire, edge), (service.identity, dependency))
                dependency_cursor += 1
        self.assertEqual(dependency_cursor, dependency_count)
        self.assertEqual(manifest.topological_identities, (0x100, 0x200, 0x300, 0x400, 0x500))

    def test_service_table_order_and_capability_order_do_not_change_bytes(self) -> None:
        first = self._load_text(BASE_MANIFEST)
        prefix, *blocks = BASE_MANIFEST.split("\n[[service]]")
        reordered = prefix + "".join("\n[[service]]" + block for block in reversed(blocks))
        reordered = reordered.replace(
            'capabilities = ["fs-read", "spawn-thread"]',
            'capabilities = ["spawn-thread", "fs-read"]',
        )
        second = self._load_text(reordered)
        self.assertEqual(GENERATOR.encode_manifest(first), GENERATOR.encode_manifest(second))
        self.assertEqual(first.topological_identities, (0x10, 0x20))

    def test_real_artifact_is_hashed_but_authority_remains_unbound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config" / "services.toml"
            artifact = root / "payload.bin"
            config.parent.mkdir()
            artifact.write_bytes(b"exact immutable service bytes")
            text = BASE_MANIFEST.split("\n[[service]]", maxsplit=2)[0]
            text = text.replace("artifacts_resolved = false", "artifacts_resolved = true")
            text += textwrap.dedent(
                """

                [[service]]
                identity = 0x10
                name = "alpha"
                path = "/system/alpha"
                transfer_ref = 1
                artifact = "../payload.bin"
                immutable_policy_selector = 1
                kind = "native"
                restart = "always"
                autostart = true
                resource_profile = "authenticated-service"
                capabilities = ["fs-read"]
                frame_budget_pages = 128
                tick_budget = 10000
                section_objects = 2
                section_pages = 64
                dependencies = []
                """
            )
            config.write_text(text, encoding="utf-8", newline="\n")
            manifest = GENERATOR.load_manifest(config)
            self.assertTrue(manifest.artifacts_resolved)
            self.assertEqual(manifest.services[0].content_hash, hashlib.sha256(artifact.read_bytes()).digest())
            self.assertEqual(manifest.services[0].content_source, "artifact:../payload.bin")

            header = root / "artifact-backed.h"
            result = subprocess.run(
                [
                    sys.executable,
                    str(GENERATOR_PATH),
                    "--input",
                    str(config),
                    "--header",
                    str(header),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("artifact-backed/authority-unbound", result.stdout)
            generated = header.read_text(encoding="ascii")
            self.assertIn("kBootServiceManifestArtifactsResolved = true", generated)
            self.assertIn("kBootServiceManifestActivationReady = false", generated)

        self._assert_rejected(
            BASE_MANIFEST.replace("artifacts_resolved = false", "artifacts_resolved = true"),
            "staged content is forbidden",
        )

    def test_separate_authority_binds_exact_manifest_without_enabling_activation(self) -> None:
        authority_text = textwrap.dedent(
            """\
            [authority]
            format_version = 1
            trust_source = "authenticated-kernel-image"
            authority_identity = 0x400
            manifest_identity = 0x100
            signer_identity = 0x200
            profile_identity = 0x300
            allowed_capabilities = ["serial-console", "fs-read", "spawn-thread"]
            allowed_immutable_policies = [1]
            allowed_service_kinds = ["native", "broker"]
            allowed_resource_profiles = ["authenticated-service"]
            max_frame_budget_pages = 256
            max_tick_budget = 20000
            max_section_objects = 3
            max_section_pages = 128
            max_services = 2
            max_dependencies = 1
            """
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "services.toml"
            authority_path = root / "authority.toml"
            artifact_root = root / "artifacts"
            artifact_root.mkdir()
            config.write_text(BASE_MANIFEST, encoding="utf-8", newline="\n")
            authority_path.write_text(authority_text, encoding="utf-8", newline="\n")
            (artifact_root / "alpha.elf").write_bytes(b"alpha exact ELF")
            (artifact_root / "beta.elf").write_bytes(b"beta exact ELF")
            manifest = GENERATOR.load_manifest(
                config,
                artifact_root=artifact_root,
                artifact_mappings={"alpha": "alpha.elf", "beta": "beta.elf"},
                retain_artifact_bytes=True,
            )
            policy = GENERATOR.load_authority(authority_path, manifest)
            wire = GENERATOR.encode_manifest(manifest)
            package = GENERATOR.render_package_header(manifest, wire, "services.toml", policy)
            audit = json.loads(GENERATOR.normalized_json(manifest, wire, policy))

            self.assertIn("kBootServicePackageAuthorityBound = true", package)
            self.assertIn("kBootServicePackageManifestAuthority", package)
            self.assertIn("kBootServicePackageDefinition", package)
            self.assertIn("kServiceManifestAuthoritySealed", package)
            self.assertIn("kBootServicePackageBootstrapPlansBound = false", package)
            self.assertIn("kBootServicePackageActivationReady = false", package)
            self.assertTrue(audit["authority_bound"])
            self.assertFalse(audit["bootstrap_plans_bound"])
            self.assertFalse(audit["activation_ready"])
            self.assertEqual(audit["authority"]["max_services"], 2)

            denied = authority_text.replace(
                '["serial-console", "fs-read", "spawn-thread"]', '["serial-console"]'
            )
            authority_path.write_text(denied, encoding="utf-8", newline="\n")
            with self.assertRaisesRegex(GENERATOR.ManifestError, "capability ceiling denied"):
                GENERATOR.load_authority(authority_path, manifest)

        with tempfile.TemporaryDirectory() as temporary:
            authority_path = Path(temporary) / "authority.toml"
            authority_path.write_text(authority_text, encoding="utf-8", newline="\n")
            with self.assertRaisesRegex(GENERATOR.ManifestError, "resolved executable artifacts"):
                GENERATOR.load_authority(authority_path, self._load_text(BASE_MANIFEST))

    def test_repository_authority_is_independent_and_matches_manifest_identity(self) -> None:
        source_manifest = GENERATOR.load_manifest(CONFIG_PATH)
        authority_document = GENERATOR._load_toml(AUTHORITY_PATH)
        table = authority_document["authority"]
        self.assertEqual(table["trust_source"], GENERATOR.AUTHORITY_TRUST_SOURCE)
        self.assertEqual(table["manifest_identity"], source_manifest.manifest_identity)
        self.assertEqual(table["signer_identity"], source_manifest.signer_identity)
        self.assertEqual(table["profile_identity"], source_manifest.profile_identity)
        self.assertNotIn("authority", GENERATOR._load_toml(CONFIG_PATH))

        cmake = (REPO_ROOT / "kernel" / "CMakeLists.txt").read_text(encoding="utf-8")
        self.assertIn("set(DUETOS_SERVICE_AUTHORITY_CONFIG", cmake)
        self.assertIn('--authority "${DUETOS_SERVICE_AUTHORITY_CONFIG}"', cmake)
        self.assertIn('"${DUETOS_SERVICE_AUTHORITY_CONFIG}"\n        ${DUETOS_SERVICE_ARTIFACTS}', cmake)
        self.assertIn(
            "static_assert(duetos::core::generated::kBootServicePackageAuthorityBound);",
            cmake,
        )

    def test_explicit_artifact_root_mapping_binds_exact_bytes_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "services.toml"
            config.write_text(BASE_MANIFEST, encoding="utf-8", newline="\n")
            mappings = {
                "alpha": "native-alpha/alpha.elf",
                "beta": "native-beta/beta.elf",
            }
            artifact_bytes = {
                "alpha": b"\x7fELF\x02\x01\x01\x00alpha-exact-build",
                "beta": b"\x7fELF\x02\x01\x01\x00beta-exact-build",
            }

            rendered: list[tuple[bytes, bytes, bytes, bytes]] = []
            for build_name in ("build-a", "build-b"):
                artifact_root = root / build_name
                for service_name, relative_path in mappings.items():
                    artifact = artifact_root / relative_path
                    artifact.parent.mkdir(parents=True, exist_ok=True)
                    artifact.write_bytes(artifact_bytes[service_name])

                manifest = GENERATOR.load_manifest(
                    config,
                    artifact_root,
                    mappings,
                    retain_artifact_bytes=True,
                )
                wire = GENERATOR.encode_manifest(manifest)
                manifest_header = GENERATOR.render_header(manifest, wire, "services.toml").encode(
                    "ascii"
                )
                package_header = GENERATOR.render_package_header(
                    manifest, wire, "services.toml"
                ).encode("ascii")
                normalized = GENERATOR.normalized_json(manifest, wire).encode("ascii")
                rendered.append((wire, manifest_header, package_header, normalized))

                self.assertTrue(manifest.artifacts_resolved)
                for service in manifest.services:
                    self.assertEqual(service.artifact_bytes, artifact_bytes[service.name])
                    self.assertEqual(
                        service.content_hash,
                        hashlib.sha256(artifact_bytes[service.name]).digest(),
                    )
                    self.assertEqual(
                        service.content_source,
                        f"artifact-map:{mappings[service.name]}",
                    )

            self.assertEqual(rendered[0], rendered[1])
            reversed_manifest = GENERATOR.load_manifest(
                root / "services.toml",
                root / "build-a",
                dict(reversed(tuple(mappings.items()))),
                retain_artifact_bytes=True,
            )
            reversed_wire = GENERATOR.encode_manifest(reversed_manifest)
            self.assertEqual(reversed_wire, rendered[0][0])
            self.assertEqual(
                GENERATOR.render_package_header(
                    reversed_manifest, reversed_wire, "services.toml"
                ).encode("ascii"),
                rendered[0][2],
            )
            prefix, *service_blocks = BASE_MANIFEST.split("\n[[service]]")
            reordered_config = root / "reordered.toml"
            reordered_config.write_text(
                prefix
                + "".join(
                    "\n[[service]]" + block for block in reversed(service_blocks)
                ),
                encoding="utf-8",
                newline="\n",
            )
            reordered_manifest = GENERATOR.load_manifest(
                reordered_config,
                root / "build-a",
                mappings,
                retain_artifact_bytes=True,
            )
            reordered_wire = GENERATOR.encode_manifest(reordered_manifest)
            self.assertEqual(reordered_wire, rendered[0][0])
            self.assertEqual(
                GENERATOR.render_package_header(
                    reordered_manifest, reordered_wire, "services.toml"
                ).encode("ascii"),
                rendered[0][2],
            )
            streamed = GENERATOR.load_manifest(root / "services.toml", root / "build-a", mappings)
            self.assertTrue(all(service.artifact_bytes is None for service in streamed.services))
            self.assertEqual(
                sum(service.artifact_byte_count for service in streamed.services),
                sum(len(content) for content in artifact_bytes.values()),
            )
            package_text = rendered[0][2].decode("ascii")
            audit = json.loads(rendered[0][3].decode("ascii"))
            self.assertFalse(audit["activation_ready"])
            self.assertFalse(audit["authority_bound"])
            self.assertFalse(audit["bootstrap_plans_bound"])
            self.assertEqual(
                {row["name"]: row["content_bytes"] for row in audit["services"]},
                {name: len(content) for name, content in artifact_bytes.items()},
            )
            self.assertIn("kBootServicePackageArtifactsResolved = true", package_text)
            self.assertIn("kBootServicePackageAuthorityBound = false", package_text)
            self.assertIn("kBootServicePackageBootstrapPlansBound = false", package_text)
            self.assertIn("kBootServicePackageActivationReady = false", package_text)
            self.assertIn("kBootServicePackageExecutableObjects[]", package_text)
            self.assertNotIn("ServiceObjectPackageDefinitionV1", package_text)
            for service in reversed_manifest.services:
                symbol = f"kBootServiceArtifactRef{service.transfer_ref:08X}Bytes"
                match = re.search(
                    rf"\b{symbol}\[\] = \{{(.*?)\n\}};",
                    package_text,
                    flags=re.DOTALL,
                )
                self.assertIsNotNone(match, symbol)
                embedded = bytes(
                    int(value, 16) for value in re.findall(r"0x([0-9A-F]{2})", match.group(1))
                )
                self.assertEqual(embedded, artifact_bytes[service.name])

            output_root = root / "outputs"
            command = [
                sys.executable,
                str(GENERATOR_PATH),
                "--input",
                str(config),
                "--artifact-root",
                str(root / "build-a"),
            ]
            for service_name, relative_path in mappings.items():
                command.extend(["--artifact-map", f"{service_name}={relative_path}"])
            command.extend(
                [
                    "--header",
                    str(output_root / "manifest.h"),
                    "--binary",
                    str(output_root / "manifest.bin"),
                    "--normalized",
                    str(output_root / "manifest.json"),
                    "--package-header",
                    str(output_root / "package.h"),
                ]
            )
            generated = subprocess.run(
                command, cwd=REPO_ROOT, text=True, capture_output=True, check=False
            )
            self.assertEqual(generated.returncode, 0, generated.stderr)
            self.assertIn("artifact-backed/authority-unbound", generated.stdout)
            checked = subprocess.run(
                command + ["--check"],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertEqual((output_root / "package.h").read_bytes(), rendered[0][2])

    def test_artifact_root_mapping_rejects_ambiguous_or_escaping_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "services.toml"
            config.write_text(BASE_MANIFEST, encoding="utf-8", newline="\n")
            artifact_root = root / "artifacts"
            (artifact_root / "native-alpha").mkdir(parents=True)
            (artifact_root / "native-beta").mkdir(parents=True)
            (artifact_root / "native-alpha" / "alpha.elf").write_bytes(b"alpha")
            (artifact_root / "native-beta" / "beta.elf").write_bytes(b"beta")
            valid = {
                "alpha": "native-alpha/alpha.elf",
                "beta": "native-beta/beta.elf",
            }

            hostile_mappings = {
                "missing": {"alpha": valid["alpha"]},
                "extra": {**valid, "gamma": "gamma.elf"},
                "parent traversal": {**valid, "beta": "../beta.elf"},
                "absolute": {**valid, "beta": "/beta.elf"},
                "backslash": {**valid, "beta": "native-beta\\beta.elf"},
            }
            for label, mappings in hostile_mappings.items():
                with self.subTest(label=label):
                    with self.assertRaises(GENERATOR.ManifestError):
                        GENERATOR.load_manifest(config, artifact_root, mappings)

            with self.assertRaisesRegex(GENERATOR.ManifestError, "duplicate service"):
                GENERATOR.parse_artifact_mappings(
                    ["alpha=native-alpha/alpha.elf", "alpha=other.elf"]
                )
            with self.assertRaisesRegex(GENERATOR.ManifestError, "duplicate artifact path"):
                GENERATOR.parse_artifact_mappings(
                    ["alpha=same.elf", "beta=same.elf"]
                )
            with self.assertRaisesRegex(GENERATOR.ManifestError, "supplied together"):
                GENERATOR.load_manifest(config, artifact_root, None)

            hardlink = artifact_root / "native-beta" / "alpha-hardlink.elf"
            try:
                os.link(artifact_root / "native-alpha" / "alpha.elf", hardlink)
            except OSError:
                pass
            else:
                with self.assertRaisesRegex(GENERATOR.ManifestError, "same artifact"):
                    GENERATOR.load_manifest(
                        config,
                        artifact_root,
                        {**valid, "beta": "native-beta/alpha-hardlink.elf"},
                    )

            with mock.patch.object(GENERATOR, "MAX_EMBEDDED_PACKAGE_BYTES", 8):
                streamed = GENERATOR.load_manifest(config, artifact_root, valid)
                self.assertTrue(streamed.artifacts_resolved)
                with self.assertRaisesRegex(GENERATOR.ManifestError, "embedded"):
                    GENERATOR.load_manifest(
                        config,
                        artifact_root,
                        valid,
                        retain_artifact_bytes=True,
                    )

            empty = artifact_root / "native-beta" / "beta.elf"
            empty.write_bytes(b"")
            with self.assertRaisesRegex(GENERATOR.ManifestError, "size must be"):
                GENERATOR.load_manifest(config, artifact_root, valid)

            output = root / "must-not-exist.h"
            result = subprocess.run(
                [
                    sys.executable,
                    str(GENERATOR_PATH),
                    "--input",
                    str(config),
                    "--header",
                    str(output),
                    "--package-header",
                    str(root / "package.h"),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("requires resolved artifacts", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertFalse(output.exists())

    def test_long_artifact_path_fails_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "services.toml"
            output = root / "manifest.h"
            long_path = "a" * (GENERATOR.MAX_ARTIFACT_PATH_BYTES + 1)
            text = BASE_MANIFEST.split("\n[[service]]", maxsplit=2)[0]
            text = text.replace("artifacts_resolved = false", "artifacts_resolved = true")
            text += textwrap.dedent(
                f"""

                [[service]]
                identity = 0x10
                name = "alpha"
                path = "/system/alpha"
                transfer_ref = 1
                artifact = "{long_path}"
                immutable_policy_selector = 1
                kind = "native"
                restart = "always"
                autostart = true
                resource_profile = "authenticated-service"
                capabilities = ["fs-read"]
                frame_budget_pages = 128
                tick_budget = 10000
                section_objects = 2
                section_pages = 64
                dependencies = []
                """
            )
            config.write_text(text, encoding="utf-8", newline="\n")
            with self.assertRaises(GENERATOR.ManifestError) as caught:
                GENERATOR.load_manifest(config)
            self.assertIn(str(GENERATOR.MAX_ARTIFACT_PATH_BYTES), str(caught.exception))

            result = subprocess.run(
                [
                    sys.executable,
                    str(GENERATOR_PATH),
                    "--input",
                    str(config),
                    "--header",
                    str(output),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn(str(GENERATOR.MAX_ARTIFACT_PATH_BYTES), result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertFalse(output.exists())

    def test_cli_outputs_are_reproducible_and_stale_check_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            header = root / "manifest.h"
            binary = root / "manifest.bin"
            normalized = root / "manifest.json"
            command = [
                sys.executable,
                str(GENERATOR_PATH),
                "--input",
                str(CONFIG_PATH),
                "--header",
                str(header),
                "--binary",
                str(binary),
                "--normalized",
                str(normalized),
            ]
            first = subprocess.run(command, cwd=REPO_ROOT, text=True, capture_output=True, check=False)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertIn("staged-artifacts/authority-unbound", first.stdout)
            first_outputs = (header.read_bytes(), binary.read_bytes(), normalized.read_bytes())
            second = subprocess.run(command, cwd=REPO_ROOT, text=True, capture_output=True, check=False)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(first_outputs, (header.read_bytes(), binary.read_bytes(), normalized.read_bytes()))
            audit = json.loads(normalized.read_text(encoding="ascii"))
            self.assertEqual(audit["wire_sha256"], hashlib.sha256(binary.read_bytes()).hexdigest())
            self.assertFalse(audit["activation_ready"])
            self.assertFalse(audit["artifacts_resolved"])
            self.assertFalse(audit["authority_bound"])
            self.assertFalse(audit["bootstrap_plans_bound"])

            checked = subprocess.run(command + ["--check"], cwd=REPO_ROOT, text=True, capture_output=True)
            self.assertEqual(checked.returncode, 0, checked.stderr)
            header.write_text("stale\n", encoding="ascii")
            stale = subprocess.run(command + ["--check"], cwd=REPO_ROOT, text=True, capture_output=True)
            self.assertEqual(stale.returncode, 2)
            self.assertIn("stale", stale.stderr)

    def test_generator_constants_match_production_contract(self) -> None:
        header = (REPO_ROOT / "kernel" / "core" / "service_manifest.h").read_text(encoding="utf-8")
        expected = {
            "kServiceManifestVersion1": GENERATOR.FORMAT_VERSION,
            "kServiceManifestV1HeaderBytes": GENERATOR.HEADER_BYTES,
            "kServiceManifestV1ServiceBytes": GENERATOR.SERVICE_BYTES,
            "kServiceManifestV1DependencyBytes": GENERATOR.DEPENDENCY_BYTES,
            "kServiceManifestMaximumServices": GENERATOR.MAX_SERVICES,
            "kServiceManifestMaximumDependenciesPerService": GENERATOR.MAX_DEPENDENCIES_PER_SERVICE,
            "kServiceManifestMaximumDependencies": GENERATOR.MAX_DEPENDENCIES,
            "kServiceManifestServiceNameCapacity": GENERATOR.MAX_NAME_BYTES,
            "kServiceManifestExecutablePathCapacity": GENERATOR.MAX_PATH_BYTES,
            "kServiceManifestPositiveTransferRefMaximum": GENERATOR.MAX_TRANSFER_REF,
            "kServiceManifestCapabilityMaskV1": GENERATOR.MAX_CAPABILITY_MASK,
        }
        for symbol, value in expected.items():
            match = re.search(rf"\b{symbol}\s*=\s*(0x[0-9A-Fa-f]+|[0-9]+)", header)
            self.assertIsNotNone(match, symbol)
            self.assertEqual(int(match.group(1), 0), value, symbol)

    def test_hostile_documents_fail_closed(self) -> None:
        cases = {
            "unknown key": BASE_MANIFEST + "unexpected = 1\n",
            "boolean confusion": BASE_MANIFEST.replace("autostart = true", "autostart = 1", 1),
            "zero identity": BASE_MANIFEST.replace("\nidentity = 0x10\n", "\nidentity = 0x0\n", 1),
            "duplicate identity": BASE_MANIFEST.replace("\nidentity = 0x20\n", "\nidentity = 0x10\n", 1),
            "duplicate name": BASE_MANIFEST.replace('name = "beta"', 'name = "alpha"', 1),
            "duplicate transfer": BASE_MANIFEST.replace("transfer_ref = 2", "transfer_ref = 1", 1),
            "bad name": BASE_MANIFEST.replace('name = "alpha"', 'name = "Alpha"', 1),
            "bad path": BASE_MANIFEST.replace('path = "/system/alpha"', 'path = "/system/../alpha"', 1),
            "unknown capability": BASE_MANIFEST.replace('"spawn-thread"', '"root"', 1),
            "duplicate capability": BASE_MANIFEST.replace(
                '["fs-read", "spawn-thread"]', '["fs-read", "fs-read"]', 1
            ),
            "missing dependency": BASE_MANIFEST.replace('["alpha"]', '["missing"]', 1),
            "self dependency": BASE_MANIFEST.replace('["alpha"]', '["beta"]', 1),
            "budget overflow": BASE_MANIFEST.replace("frame_budget_pages = 128", "frame_budget_pages = 8193", 1),
            "missing required": BASE_MANIFEST.replace("tick_budget = 10000\n", "", 1),
        }
        for label, text in cases.items():
            with self.subTest(label=label):
                self._assert_rejected(text)

        cycle = BASE_MANIFEST.replace("dependencies = []", 'dependencies = ["beta"]', 1)
        self._assert_rejected(cycle, "cycle")


if __name__ == "__main__":
    unittest.main(verbosity=2)
