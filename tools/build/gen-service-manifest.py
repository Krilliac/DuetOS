#!/usr/bin/env python3
"""Generate DuetOS's canonical ServiceManifest v1 package.

The input is a small TOML policy document.  The output bytes exactly match
kernel/core/service_manifest.{h,cpp}: a 64-byte little-endian header, sorted
256-byte service rows, and contiguous sorted 16-byte dependency edges.

This generator is intentionally stdlib-only and fail-closed.  It rejects
unknown keys, non-canonical text, cycles, out-of-range budgets, and unstable
artifact reads.  A separately supplied authority policy may bind the exact
manifest hash/extent to an authenticated-kernel-image trust root; no policy
ceiling is inferred from the manifest it constrains.

Build-tree packaging uses an explicit artifact root plus one canonical
SERVICE=RELATIVE/PATH mapping for every manifest row.  The package header then
embeds the same bytes that were hashed.  Bootstrap-plan and activation
readiness remain hard-disabled even when the separate authority is bound.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import struct
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

try:
    import tomllib
except ModuleNotFoundError as error:  # pragma: no cover - Python < 3.11
    raise SystemExit("gen-service-manifest.py requires Python 3.11 or newer") from error


FORMAT_VERSION = 1
HEADER_BYTES = 64
SERVICE_BYTES = 256
DEPENDENCY_BYTES = 16
MAX_SERVICES = 64
MAX_DEPENDENCIES = 256
MAX_DEPENDENCIES_PER_SERVICE = 8
MAX_NAME_BYTES = 32
MAX_PATH_BYTES = 128
MAX_CONFIG_BYTES = 256 * 1024
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 1024 * 1024 * 1024
MAX_EMBEDDED_PACKAGE_BYTES = 64 * 1024 * 1024
MAX_ARTIFACT_PATH_BYTES = 4096
MAX_TRANSFER_REF = 0x7FFFFFFF
MAX_CAPABILITY_MASK = 0x1FFE
MAX_FRAME_BUDGET = 8192
MAX_TICK_BUDGET = 1 << 40
MAX_SECTION_OBJECTS = 4
MAX_SECTION_PAGES = 2048
RESERVED_IDENTITY = (1 << 64) - 1
STAGED_HASH_DOMAIN = b"duetos-staged-service-v1\0"
GENERATOR_VERSION = 1

KIND_VALUES = {"native": 1, "win32": 2, "linux": 3, "broker": 4}
RESTART_VALUES = {"never": 0, "always": 1, "on-failure": 2}
RESOURCE_VALUES = {"sandbox": 0, "trusted": 1, "authenticated-service": 2}
RESOURCE_LIMITS = {
    "sandbox": (2, 8, 8, 1000),
    "trusted": (2, 1024, MAX_FRAME_BUDGET, MAX_TICK_BUDGET),
    "authenticated-service": (4, 2048, MAX_FRAME_BUDGET, MAX_TICK_BUDGET),
}
CAPABILITY_BITS = {
    "serial-console": 1,
    "fs-read": 2,
    "debug": 3,
    "fs-write": 4,
    "spawn-thread": 5,
    "net": 6,
    "input": 7,
    "net-admin": 8,
    "diag": 9,
    "sched-priority": 10,
    "power-tune": 11,
    "service-control": 12,
}

TOP_LEVEL_KEYS = {"manifest", "service"}
AUTHORITY_TOP_LEVEL_KEYS = {"authority"}
MANIFEST_KEYS = {
    "format_version",
    "manifest_identity",
    "signer_identity",
    "profile_identity",
    "artifacts_resolved",
}
SERVICE_KEYS = {
    "identity",
    "name",
    "path",
    "transfer_ref",
    "artifact",
    "staged_content_label",
    "immutable_policy_selector",
    "kind",
    "restart",
    "autostart",
    "resource_profile",
    "capabilities",
    "frame_budget_pages",
    "tick_budget",
    "section_objects",
    "section_pages",
    "dependencies",
}
AUTHORITY_KEYS = {
    "format_version",
    "trust_source",
    "authority_identity",
    "manifest_identity",
    "signer_identity",
    "profile_identity",
    "allowed_capabilities",
    "allowed_immutable_policies",
    "allowed_service_kinds",
    "allowed_resource_profiles",
    "max_frame_budget_pages",
    "max_tick_budget",
    "max_section_objects",
    "max_section_pages",
    "max_services",
    "max_dependencies",
}
AUTHORITY_TRUST_SOURCE = "authenticated-kernel-image"

NAME_RE = re.compile(r"[a-z][a-z0-9._-]{0,31}\Z", re.ASCII)
PATH_RE = re.compile(r"/[a-z0-9._/-]{1,127}\Z", re.ASCII)
STAGED_LABEL_RE = re.compile(r"[a-z][a-z0-9._/-]{0,127}\Z", re.ASCII)
ARTIFACT_MAP_PATH_RE = re.compile(r"[a-z0-9][a-z0-9._/-]*\Z", re.ASCII)
SOURCE_LABEL_RE = re.compile(r"[A-Za-z0-9._/-]{1,4096}\Z", re.ASCII)


class ManifestError(ValueError):
    """A deterministic, user-facing manifest validation failure."""


@dataclass(frozen=True)
class Artifact:
    relative_path: str
    file_identity: str
    content: bytes | None
    byte_count: int
    sha256: bytes


@dataclass(frozen=True)
class Service:
    identity: int
    name: str
    path: str
    transfer_ref: int
    content_hash: bytes
    content_source: str
    artifact_bytes: bytes | None
    artifact_byte_count: int
    immutable_policy_selector: int
    kind: str
    restart: str
    autostart: bool
    resource_profile: str
    capabilities: tuple[str, ...]
    capability_mask: int
    frame_budget_pages: int
    tick_budget: int
    section_objects: int
    section_pages: int
    dependency_names: tuple[str, ...]
    dependency_identities: tuple[int, ...]


@dataclass(frozen=True)
class Manifest:
    manifest_identity: int
    signer_identity: int
    profile_identity: int
    artifacts_resolved: bool
    services: tuple[Service, ...]
    topological_identities: tuple[int, ...]

    @property
    def dependency_count(self) -> int:
        return sum(len(service.dependency_identities) for service in self.services)


@dataclass(frozen=True)
class AuthorityPolicy:
    authority_identity: int
    manifest_identity: int
    signer_identity: int
    profile_identity: int
    capability_mask: int
    immutable_policy_mask: int
    service_kind_mask: int
    resource_profile_mask: int
    max_frame_budget_pages: int
    max_tick_budget: int
    max_section_objects: int
    max_section_pages: int
    max_services: int
    max_dependencies: int


def _reject_unknown(table: dict[str, Any], allowed: set[str], context: str) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise ManifestError(f"{context}: unknown key(s): {', '.join(unknown)}")


def _require_int(table: dict[str, Any], key: str, context: str, minimum: int, maximum: int) -> int:
    value = table.get(key)
    if type(value) is not int or value < minimum or value > maximum:
        raise ManifestError(f"{context}.{key}: expected integer in [{minimum}, {maximum}]")
    return value


def _require_bool(table: dict[str, Any], key: str, context: str) -> bool:
    value = table.get(key)
    if type(value) is not bool:
        raise ManifestError(f"{context}.{key}: expected boolean")
    return value


def _require_string(table: dict[str, Any], key: str, context: str) -> str:
    value = table.get(key)
    if type(value) is not str:
        raise ManifestError(f"{context}.{key}: expected string")
    return value


def _require_string_list(table: dict[str, Any], key: str, context: str) -> tuple[str, ...]:
    value = table.get(key)
    if type(value) is not list or any(type(item) is not str for item in value):
        raise ManifestError(f"{context}.{key}: expected an array of strings")
    return tuple(value)


def _require_int_list(
    table: dict[str, Any], key: str, context: str, minimum: int, maximum: int
) -> tuple[int, ...]:
    value = table.get(key)
    if type(value) is not list or not value:
        raise ManifestError(f"{context}.{key}: expected a non-empty integer array")
    if any(type(item) is not int or item < minimum or item > maximum for item in value):
        raise ManifestError(
            f"{context}.{key}: values must be integers in [{minimum}, {maximum}]"
        )
    if len(set(value)) != len(value):
        raise ManifestError(f"{context}.{key}: duplicate value")
    return tuple(value)


def _identity(table: dict[str, Any], key: str, context: str) -> int:
    return _require_int(table, key, context, 1, RESERVED_IDENTITY - 1)


def _canonical_path(value: str, context: str) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) > MAX_PATH_BYTES or not PATH_RE.fullmatch(value):
        raise ManifestError(f"{context}.path: expected canonical absolute ASCII path")
    components = value[1:].split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise ManifestError(f"{context}.path: empty, '.' and '..' components are forbidden")
    return value


def _read_artifact(
    artifact_path: Path,
    relative_path: str,
    context: str,
    retain_content: bool,
) -> Artifact:
    try:
        with artifact_path.open("rb") as artifact:
            before = os.fstat(artifact.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ManifestError(f"{context}: artifact must be a regular file")
            if before.st_size <= 0 or before.st_size > MAX_ARTIFACT_BYTES:
                raise ManifestError(
                    f"{context}: size must be in [1, {MAX_ARTIFACT_BYTES}] bytes"
                )
            if retain_content and before.st_size > MAX_EMBEDDED_PACKAGE_BYTES:
                raise ManifestError(
                    f"{context}: embedded package artifact exceeds "
                    f"{MAX_EMBEDDED_PACKAGE_BYTES} bytes"
                )
            digest = hashlib.sha256()
            content = bytearray() if retain_content else None
            byte_count = 0
            while chunk := artifact.read(1024 * 1024):
                digest.update(chunk)
                byte_count += len(chunk)
                if content is not None:
                    content.extend(chunk)
            after = os.fstat(artifact.fileno())
    except OSError as error:
        raise ManifestError(f"{context}: cannot read {relative_path!r}: {error}") from error

    fingerprint_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    fingerprint_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if fingerprint_before != fingerprint_after or byte_count != before.st_size:
        raise ManifestError(f"{context}: file changed while reading")
    return Artifact(
        relative_path=relative_path,
        file_identity=(
            f"inode:{before.st_dev}:{before.st_ino}"
            if before.st_ino != 0
            else f"path:{os.path.normcase(str(artifact_path))}"
        ),
        content=bytes(content) if content is not None else None,
        byte_count=byte_count,
        sha256=digest.digest(),
    )


def _hash_artifact(
    path_text: str,
    config_path: Path,
    context: str,
    retain_content: bool,
) -> Artifact:
    try:
        path_bytes = path_text.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ManifestError(f"{context}.artifact: path is not valid UTF-8") from error
    if len(path_bytes) == 0 or len(path_bytes) > MAX_ARTIFACT_PATH_BYTES:
        raise ManifestError(
            f"{context}.artifact: UTF-8 path length must be in [1, {MAX_ARTIFACT_PATH_BYTES}] bytes"
        )

    try:
        relative = Path(path_text)
        if relative.is_absolute():
            raise ValueError("absolute paths are forbidden")
        config_directory = config_path.resolve().parent
        repo_root = config_directory.parent
        artifact_path = (config_directory / relative).resolve()
        artifact_path.relative_to(repo_root)
    except (OSError, RuntimeError, ValueError) as error:
        raise ManifestError(f"{context}.artifact: invalid repository-relative path: {error}") from error

    return _read_artifact(
        artifact_path,
        relative.as_posix(),
        f"{context}.artifact",
        retain_content,
    )


def _canonical_artifact_map_path(path_text: str, context: str) -> str:
    try:
        encoded = path_text.encode("ascii", errors="strict")
    except UnicodeEncodeError as error:
        raise ManifestError(f"{context}: path must be canonical ASCII") from error
    if len(encoded) == 0 or len(encoded) > MAX_ARTIFACT_PATH_BYTES:
        raise ManifestError(
            f"{context}: path length must be in [1, {MAX_ARTIFACT_PATH_BYTES}] bytes"
        )
    if "\\" in path_text or not ARTIFACT_MAP_PATH_RE.fullmatch(path_text):
        raise ManifestError(f"{context}: expected a canonical relative POSIX path")
    components = path_text.split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise ManifestError(f"{context}: empty, '.' and '..' components are forbidden")
    pure = PurePosixPath(path_text)
    if pure.is_absolute():
        raise ManifestError(f"{context}: absolute paths are forbidden")
    return pure.as_posix()


def _mapped_artifact(
    artifact_root: Path,
    path_text: str,
    context: str,
    retain_content: bool,
) -> Artifact:
    relative_path = _canonical_artifact_map_path(path_text, context)
    try:
        artifact_path = (artifact_root / Path(*PurePosixPath(relative_path).parts)).resolve()
        artifact_path.relative_to(artifact_root)
    except (OSError, RuntimeError, ValueError) as error:
        raise ManifestError(f"{context}: path escapes artifact root: {error}") from error
    return _read_artifact(artifact_path, relative_path, context, retain_content)


def _content_hash(
    table: dict[str, Any], config_path: Path, artifacts_resolved: bool, context: str,
    mapped_artifact: Artifact | None = None,
    retain_content: bool = False,
) -> tuple[bytes, str, bytes | None, int]:
    has_artifact = "artifact" in table
    has_staged = "staged_content_label" in table
    if has_artifact == has_staged:
        raise ManifestError(f"{context}: specify exactly one of artifact or staged_content_label")
    if mapped_artifact is not None:
        if not has_staged:
            raise ManifestError(f"{context}: artifact-map may only resolve a staged_content_label row")
        return (
            mapped_artifact.sha256,
            f"artifact-map:{mapped_artifact.relative_path}",
            mapped_artifact.content,
            mapped_artifact.byte_count,
        )
    if has_artifact:
        artifact = _hash_artifact(
            _require_string(table, "artifact", context),
            config_path,
            context,
            retain_content,
        )
        return (
            artifact.sha256,
            f"artifact:{artifact.relative_path}",
            artifact.content,
            artifact.byte_count,
        )

    label = _require_string(table, "staged_content_label", context)
    if artifacts_resolved:
        raise ManifestError(f"{context}: staged content is forbidden when artifacts_resolved=true")
    if not STAGED_LABEL_RE.fullmatch(label):
        raise ManifestError(f"{context}.staged_content_label: invalid canonical label")
    return (
        hashlib.sha256(STAGED_HASH_DOMAIN + label.encode("ascii")).digest(),
        f"staged:{label}",
        None,
        0,
    )


def _load_toml(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ManifestError(f"cannot read {path}: {error}") from error
    if len(raw) == 0 or len(raw) > MAX_CONFIG_BYTES:
        raise ManifestError(f"manifest source size must be in [1, {MAX_CONFIG_BYTES}] bytes")
    try:
        document = tomllib.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ManifestError(f"invalid UTF-8 TOML: {error}") from error
    if type(document) is not dict:
        raise ManifestError("top level must be a TOML table")
    return document


def load_manifest(
    path: Path,
    artifact_root: Path | None = None,
    artifact_mappings: dict[str, str] | None = None,
    retain_artifact_bytes: bool = False,
) -> Manifest:
    document = _load_toml(path)
    _reject_unknown(document, TOP_LEVEL_KEYS, "document")
    manifest_table = document.get("manifest")
    service_tables = document.get("service")
    if type(manifest_table) is not dict:
        raise ManifestError("document.manifest: expected table")
    if type(service_tables) is not list or not service_tables:
        raise ManifestError("document.service: expected at least one array-of-tables entry")
    if len(service_tables) > MAX_SERVICES:
        raise ManifestError(f"document.service: maximum is {MAX_SERVICES}")

    _reject_unknown(manifest_table, MANIFEST_KEYS, "manifest")
    version = _require_int(manifest_table, "format_version", "manifest", 1, 0xFFFF)
    if version != FORMAT_VERSION:
        raise ManifestError(f"manifest.format_version: unsupported version {version}")
    manifest_identity = _identity(manifest_table, "manifest_identity", "manifest")
    signer_identity = _identity(manifest_table, "signer_identity", "manifest")
    profile_identity = _identity(manifest_table, "profile_identity", "manifest")
    configured_artifacts_resolved = _require_bool(
        manifest_table, "artifacts_resolved", "manifest"
    )

    mapping_contract = artifact_root is not None or artifact_mappings is not None
    if (artifact_root is None) != (artifact_mappings is None):
        raise ManifestError("artifact-root and artifact-map must be supplied together")
    resolved_artifact_root: Path | None = None
    mappings: dict[str, str] = {}
    mapped_relative_paths: set[str] = set()
    if mapping_contract:
        if configured_artifacts_resolved:
            raise ManifestError(
                "artifact-root mapping requires an artifacts_resolved=false staged manifest source"
            )
        assert artifact_root is not None and artifact_mappings is not None
        try:
            resolved_artifact_root = artifact_root.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise ManifestError(f"artifact-root: cannot resolve directory: {error}") from error
        if not resolved_artifact_root.is_dir():
            raise ManifestError("artifact-root: expected a directory")
        for name, relative_path in artifact_mappings.items():
            if type(name) is not str or not NAME_RE.fullmatch(name):
                raise ManifestError(f"artifact-map: invalid service name {name!r}")
            if type(relative_path) is not str:
                raise ManifestError(f"artifact-map[{name!r}]: path must be a string")
            canonical_relative_path = _canonical_artifact_map_path(
                relative_path, f"artifact-map[{name!r}]"
            )
            if canonical_relative_path in mapped_relative_paths:
                raise ManifestError(
                    f"artifact-map[{name!r}]: duplicate artifact path {canonical_relative_path!r}"
                )
            mapped_relative_paths.add(canonical_relative_path)
            mappings[name] = canonical_relative_path

    artifacts_resolved = configured_artifacts_resolved or mapping_contract

    partial: list[dict[str, Any]] = []
    identities: set[int] = set()
    names: set[str] = set()
    transfer_refs: set[int] = set()
    mapped_file_identities: set[str] = set()
    retained_artifact_bytes = 0
    for index, table in enumerate(service_tables):
        context = f"service[{index}]"
        if type(table) is not dict:
            raise ManifestError(f"{context}: expected table")
        _reject_unknown(table, SERVICE_KEYS, context)
        identity = _identity(table, "identity", context)
        name = _require_string(table, "name", context)
        if not NAME_RE.fullmatch(name) or len(name.encode("ascii")) > MAX_NAME_BYTES:
            raise ManifestError(f"{context}.name: expected canonical ASCII service name")
        path_text = _canonical_path(_require_string(table, "path", context), context)
        transfer_ref = _require_int(table, "transfer_ref", context, 1, MAX_TRANSFER_REF)
        if identity in identities:
            raise ManifestError(f"{context}.identity: duplicate identity {identity}")
        if name in names:
            raise ManifestError(f"{context}.name: duplicate service name {name!r}")
        if transfer_ref in transfer_refs:
            raise ManifestError(f"{context}.transfer_ref: duplicate transfer reference {transfer_ref}")
        identities.add(identity)
        names.add(name)
        transfer_refs.add(transfer_ref)

        policy = _require_int(table, "immutable_policy_selector", context, 1, 63)
        kind = _require_string(table, "kind", context)
        restart = _require_string(table, "restart", context)
        resource_profile = _require_string(table, "resource_profile", context)
        if kind not in KIND_VALUES:
            raise ManifestError(f"{context}.kind: unknown kind {kind!r}")
        if restart not in RESTART_VALUES:
            raise ManifestError(f"{context}.restart: unknown policy {restart!r}")
        if resource_profile not in RESOURCE_VALUES:
            raise ManifestError(f"{context}.resource_profile: unknown profile {resource_profile!r}")

        capabilities = _require_string_list(table, "capabilities", context)
        if len(set(capabilities)) != len(capabilities):
            raise ManifestError(f"{context}.capabilities: duplicate capability")
        unknown_caps = sorted(set(capabilities) - set(CAPABILITY_BITS))
        if unknown_caps:
            raise ManifestError(f"{context}.capabilities: unknown value(s): {', '.join(unknown_caps)}")
        capability_mask = sum(1 << CAPABILITY_BITS[name_value] for name_value in capabilities)
        if capability_mask & ~MAX_CAPABILITY_MASK:
            raise ManifestError(f"{context}.capabilities: exceeds ServiceManifest v1 mask")

        object_max, page_max, frame_max, tick_max = RESOURCE_LIMITS[resource_profile]
        frame_budget = _require_int(table, "frame_budget_pages", context, 1, frame_max)
        tick_budget = _require_int(table, "tick_budget", context, 1, tick_max)
        section_objects = _require_int(table, "section_objects", context, 1, object_max)
        section_pages = _require_int(table, "section_pages", context, 1, page_max)
        dependencies = _require_string_list(table, "dependencies", context)
        if len(dependencies) > MAX_DEPENDENCIES_PER_SERVICE:
            raise ManifestError(
                f"{context}.dependencies: maximum is {MAX_DEPENDENCIES_PER_SERVICE}"
            )
        if len(set(dependencies)) != len(dependencies):
            raise ManifestError(f"{context}.dependencies: duplicate dependency")

        mapped_artifact = None
        if mapping_contract:
            if name not in mappings:
                raise ManifestError(f"artifact-map: missing service {name!r}")
            assert resolved_artifact_root is not None
            mapped_artifact = _mapped_artifact(
                resolved_artifact_root,
                mappings[name],
                f"artifact-map[{name!r}]",
                retain_artifact_bytes,
            )
            if mapped_artifact.file_identity in mapped_file_identities:
                raise ManifestError(
                    f"artifact-map[{name!r}]: two services resolve to the same artifact"
                )
            mapped_file_identities.add(mapped_artifact.file_identity)
        content_hash, content_source, artifact_bytes, artifact_byte_count = _content_hash(
            table,
            path,
            configured_artifacts_resolved,
            context,
            mapped_artifact,
            retain_artifact_bytes,
        )
        if retain_artifact_bytes:
            if artifact_byte_count > MAX_EMBEDDED_PACKAGE_BYTES - retained_artifact_bytes:
                raise ManifestError(
                    f"embedded artifact package exceeds {MAX_EMBEDDED_PACKAGE_BYTES} bytes"
                )
            retained_artifact_bytes += artifact_byte_count
        partial.append(
            {
                "identity": identity,
                "name": name,
                "path": path_text,
                "transfer_ref": transfer_ref,
                "content_hash": content_hash,
                "content_source": content_source,
                "artifact_bytes": artifact_bytes,
                "artifact_byte_count": artifact_byte_count,
                "immutable_policy_selector": policy,
                "kind": kind,
                "restart": restart,
                "autostart": _require_bool(table, "autostart", context),
                "resource_profile": resource_profile,
                "capabilities": tuple(sorted(capabilities, key=CAPABILITY_BITS.__getitem__)),
                "capability_mask": capability_mask,
                "frame_budget_pages": frame_budget,
                "tick_budget": tick_budget,
                "section_objects": section_objects,
                "section_pages": section_pages,
                "dependency_names": dependencies,
            }
        )

    if mapping_contract:
        unexpected = sorted(set(mappings) - names)
        if unexpected:
            raise ManifestError(f"artifact-map: unexpected service {unexpected[0]!r}")

    name_to_identity = {entry["name"]: entry["identity"] for entry in partial}
    services: list[Service] = []
    total_dependencies = 0
    for entry in partial:
        missing = sorted(set(entry["dependency_names"]) - set(name_to_identity))
        if missing:
            raise ManifestError(f"service {entry['name']!r}: missing dependency {missing[0]!r}")
        if entry["name"] in entry["dependency_names"]:
            raise ManifestError(f"service {entry['name']!r}: self dependency")
        dependency_ids = tuple(sorted(name_to_identity[name] for name in entry["dependency_names"]))
        total_dependencies += len(dependency_ids)
        services.append(Service(**entry, dependency_identities=dependency_ids))
    if total_dependencies > MAX_DEPENDENCIES:
        raise ManifestError(f"dependency count exceeds {MAX_DEPENDENCIES}")

    total_artifact_bytes = sum(service.artifact_byte_count for service in services)
    if total_artifact_bytes > MAX_TOTAL_ARTIFACT_BYTES:
        raise ManifestError(f"artifact package exceeds {MAX_TOTAL_ARTIFACT_BYTES} bytes")

    services.sort(key=lambda service: service.identity)
    topological = _topological_order(services)
    return Manifest(
        manifest_identity=manifest_identity,
        signer_identity=signer_identity,
        profile_identity=profile_identity,
        artifacts_resolved=artifacts_resolved,
        services=tuple(services),
        topological_identities=topological,
    )


def load_authority(path: Path, manifest: Manifest) -> AuthorityPolicy:
    if not manifest.artifacts_resolved:
        raise ManifestError("authority binding requires resolved executable artifacts")
    document = _load_toml(path)
    _reject_unknown(document, AUTHORITY_TOP_LEVEL_KEYS, "authority document")
    table = document.get("authority")
    if type(table) is not dict:
        raise ManifestError("authority document.authority: expected table")
    _reject_unknown(table, AUTHORITY_KEYS, "authority")
    version = _require_int(table, "format_version", "authority", 1, 0xFFFF)
    if version != FORMAT_VERSION:
        raise ManifestError(f"authority.format_version: unsupported version {version}")
    trust_source = _require_string(table, "trust_source", "authority")
    if trust_source != AUTHORITY_TRUST_SOURCE:
        raise ManifestError(
            f"authority.trust_source: expected {AUTHORITY_TRUST_SOURCE!r}"
        )

    authority_identity = _identity(table, "authority_identity", "authority")
    manifest_identity = _identity(table, "manifest_identity", "authority")
    signer_identity = _identity(table, "signer_identity", "authority")
    profile_identity = _identity(table, "profile_identity", "authority")
    if manifest_identity != manifest.manifest_identity:
        raise ManifestError("authority.manifest_identity: does not match manifest source")
    if signer_identity != manifest.signer_identity:
        raise ManifestError("authority.signer_identity: does not match manifest source")
    if profile_identity != manifest.profile_identity:
        raise ManifestError("authority.profile_identity: does not match manifest source")

    capabilities = _require_string_list(table, "allowed_capabilities", "authority")
    if len(set(capabilities)) != len(capabilities):
        raise ManifestError("authority.allowed_capabilities: duplicate capability")
    unknown_capabilities = sorted(set(capabilities) - set(CAPABILITY_BITS))
    if unknown_capabilities:
        raise ManifestError(
            "authority.allowed_capabilities: unknown value(s): "
            + ", ".join(unknown_capabilities)
        )
    capability_mask = sum(1 << CAPABILITY_BITS[value] for value in capabilities)
    if capability_mask & ~MAX_CAPABILITY_MASK:
        raise ManifestError("authority.allowed_capabilities: exceeds ServiceManifest v1 mask")

    immutable_policies = _require_int_list(
        table, "allowed_immutable_policies", "authority", 1, 63
    )
    immutable_policy_mask = sum(1 << value for value in immutable_policies)

    service_kinds = _require_string_list(table, "allowed_service_kinds", "authority")
    if len(set(service_kinds)) != len(service_kinds):
        raise ManifestError("authority.allowed_service_kinds: duplicate kind")
    unknown_kinds = sorted(set(service_kinds) - set(KIND_VALUES))
    if unknown_kinds:
        raise ManifestError(
            "authority.allowed_service_kinds: unknown value(s): " + ", ".join(unknown_kinds)
        )
    service_kind_mask = sum(1 << KIND_VALUES[value] for value in service_kinds)

    resource_profiles = _require_string_list(
        table, "allowed_resource_profiles", "authority"
    )
    if len(set(resource_profiles)) != len(resource_profiles):
        raise ManifestError("authority.allowed_resource_profiles: duplicate profile")
    unknown_profiles = sorted(set(resource_profiles) - set(RESOURCE_VALUES))
    if unknown_profiles:
        raise ManifestError(
            "authority.allowed_resource_profiles: unknown value(s): "
            + ", ".join(unknown_profiles)
        )
    resource_profile_mask = sum(1 << RESOURCE_VALUES[value] for value in resource_profiles)

    policy = AuthorityPolicy(
        authority_identity=authority_identity,
        manifest_identity=manifest_identity,
        signer_identity=signer_identity,
        profile_identity=profile_identity,
        capability_mask=capability_mask,
        immutable_policy_mask=immutable_policy_mask,
        service_kind_mask=service_kind_mask,
        resource_profile_mask=resource_profile_mask,
        max_frame_budget_pages=_require_int(
            table, "max_frame_budget_pages", "authority", 1, MAX_FRAME_BUDGET
        ),
        max_tick_budget=_require_int(
            table, "max_tick_budget", "authority", 1, MAX_TICK_BUDGET
        ),
        max_section_objects=_require_int(
            table, "max_section_objects", "authority", 1, MAX_SECTION_OBJECTS
        ),
        max_section_pages=_require_int(
            table, "max_section_pages", "authority", 1, MAX_SECTION_PAGES
        ),
        max_services=_require_int(table, "max_services", "authority", 1, MAX_SERVICES),
        max_dependencies=_require_int(
            table, "max_dependencies", "authority", 0, MAX_DEPENDENCIES
        ),
    )

    if len(manifest.services) > policy.max_services:
        raise ManifestError("authority.max_services: manifest exceeds ceiling")
    if manifest.dependency_count > policy.max_dependencies:
        raise ManifestError("authority.max_dependencies: manifest exceeds ceiling")
    for service in manifest.services:
        context = f"authority service {service.name!r}"
        if service.capability_mask & ~policy.capability_mask:
            raise ManifestError(f"{context}: capability ceiling denied")
        if (policy.immutable_policy_mask & (1 << service.immutable_policy_selector)) == 0:
            raise ManifestError(f"{context}: immutable policy denied")
        if (policy.service_kind_mask & (1 << KIND_VALUES[service.kind])) == 0:
            raise ManifestError(f"{context}: service kind denied")
        if (policy.resource_profile_mask & (1 << RESOURCE_VALUES[service.resource_profile])) == 0:
            raise ManifestError(f"{context}: resource profile denied")
        if service.frame_budget_pages > policy.max_frame_budget_pages:
            raise ManifestError(f"{context}: frame budget denied")
        if service.tick_budget > policy.max_tick_budget:
            raise ManifestError(f"{context}: tick budget denied")
        if service.section_objects > policy.max_section_objects:
            raise ManifestError(f"{context}: section object ceiling denied")
        if service.section_pages > policy.max_section_pages:
            raise ManifestError(f"{context}: section page ceiling denied")
    return policy


def _topological_order(services: Iterable[Service]) -> tuple[int, ...]:
    rows = tuple(services)
    indegree = {service.identity: len(service.dependency_identities) for service in rows}
    dependents: dict[int, list[int]] = {service.identity: [] for service in rows}
    for service in rows:
        for dependency in service.dependency_identities:
            dependents[dependency].append(service.identity)
    order: list[int] = []
    ready = sorted(identity for identity, degree in indegree.items() if degree == 0)
    while ready:
        identity = ready.pop(0)
        order.append(identity)
        for dependent in sorted(dependents[identity]):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                ready.append(dependent)
                ready.sort()
    if len(order) != len(rows):
        raise ManifestError("service dependency graph contains a cycle")
    return tuple(order)


def encode_manifest(manifest: Manifest) -> bytes:
    dependency_count = manifest.dependency_count
    dependencies_offset = HEADER_BYTES + len(manifest.services) * SERVICE_BYTES
    total_size = dependencies_offset + dependency_count * DEPENDENCY_BYTES
    output = bytearray(total_size)
    struct.pack_into(
        "<IHHHHHHIIQQQIIQ",
        output,
        0,
        total_size,
        FORMAT_VERSION,
        HEADER_BYTES,
        SERVICE_BYTES,
        DEPENDENCY_BYTES,
        len(manifest.services),
        dependency_count,
        0,
        0,
        manifest.manifest_identity,
        manifest.signer_identity,
        manifest.profile_identity,
        HEADER_BYTES,
        dependencies_offset,
        0,
    )

    dependency_cursor = 0
    for index, service in enumerate(manifest.services):
        row_offset = HEADER_BYTES + index * SERVICE_BYTES
        name_bytes = service.name.encode("ascii")
        path_bytes = service.path.encode("ascii")
        struct.pack_into("<QII", output, row_offset, service.identity, service.transfer_ref,
                         service.immutable_policy_selector)
        output[row_offset + 16 : row_offset + 48] = service.content_hash
        struct.pack_into(
            "<QQQIIHHBBBBBBHI",
            output,
            row_offset + 48,
            service.capability_mask,
            service.frame_budget_pages,
            service.tick_budget,
            service.section_objects,
            service.section_pages,
            dependency_cursor,
            len(service.dependency_identities),
            len(name_bytes),
            len(path_bytes),
            KIND_VALUES[service.kind],
            RESTART_VALUES[service.restart],
            int(service.autostart),
            RESOURCE_VALUES[service.resource_profile],
            0,
            0,
        )
        output[row_offset + 96 : row_offset + 96 + len(name_bytes)] = name_bytes
        output[row_offset + 128 : row_offset + 128 + len(path_bytes)] = path_bytes
        for dependency_identity in service.dependency_identities:
            edge_offset = dependencies_offset + dependency_cursor * DEPENDENCY_BYTES
            struct.pack_into("<QQ", output, edge_offset, service.identity, dependency_identity)
            dependency_cursor += 1
    if dependency_cursor != dependency_count:
        raise AssertionError("internal dependency cursor mismatch")
    return bytes(output)


def normalized_json(
    manifest: Manifest, wire: bytes, authority: AuthorityPolicy | None = None
) -> str:
    payload = {
        "activation_ready": False,
        "artifacts_resolved": manifest.artifacts_resolved,
        "authority_bound": authority is not None,
        "bootstrap_plans_bound": False,
        "dependency_count": manifest.dependency_count,
        "format_version": FORMAT_VERSION,
        "manifest_identity": f"0x{manifest.manifest_identity:016x}",
        "profile_identity": f"0x{manifest.profile_identity:016x}",
        "service_count": len(manifest.services),
        "services": [
            {
                "autostart": service.autostart,
                "capabilities": list(service.capabilities),
                "capability_mask": f"0x{service.capability_mask:016x}",
                "content_bytes": service.artifact_byte_count or None,
                "content_sha256": service.content_hash.hex(),
                "content_source": service.content_source,
                "dependencies": [f"0x{value:016x}" for value in service.dependency_identities],
                "frame_budget_pages": service.frame_budget_pages,
                "identity": f"0x{service.identity:016x}",
                "immutable_policy_selector": service.immutable_policy_selector,
                "kind": service.kind,
                "name": service.name,
                "path": service.path,
                "resource_profile": service.resource_profile,
                "restart": service.restart,
                "section_objects": service.section_objects,
                "section_pages": service.section_pages,
                "tick_budget": service.tick_budget,
                "transfer_ref": service.transfer_ref,
            }
            for service in manifest.services
        ],
        "signer_identity": f"0x{manifest.signer_identity:016x}",
        "topological_identities": [f"0x{value:016x}" for value in manifest.topological_identities],
        "wire_bytes": len(wire),
        "wire_sha256": hashlib.sha256(wire).hexdigest(),
    }
    if authority is not None:
        payload["authority"] = {
            "authority_identity": f"0x{authority.authority_identity:016x}",
            "capability_mask": f"0x{authority.capability_mask:016x}",
            "immutable_policy_mask": f"0x{authority.immutable_policy_mask:016x}",
            "manifest_identity": f"0x{authority.manifest_identity:016x}",
            "max_dependencies": authority.max_dependencies,
            "max_frame_budget_pages": authority.max_frame_budget_pages,
            "max_section_objects": authority.max_section_objects,
            "max_section_pages": authority.max_section_pages,
            "max_services": authority.max_services,
            "max_tick_budget": authority.max_tick_budget,
            "profile_identity": f"0x{authority.profile_identity:016x}",
            "resource_profile_mask": f"0x{authority.resource_profile_mask:08x}",
            "service_kind_mask": f"0x{authority.service_kind_mask:08x}",
            "signer_identity": f"0x{authority.signer_identity:016x}",
            "trust_source": AUTHORITY_TRUST_SOURCE,
        }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def render_header(manifest: Manifest, wire: bytes, source_label: str) -> str:
    digest = hashlib.sha256(wire).digest()
    artifacts_resolved_literal = "true" if manifest.artifacts_resolved else "false"
    lines = [
        "#pragma once",
        "",
        "// Generated by tools/build/gen-service-manifest.py; do not edit.",
        f"// Source: {source_label}",
        "// These canonical bytes are neither a sealed object nor a trusted authority",
        "// snapshot. Artifact resolution only proves content hashing; boot activation",
        "// remains hard-disabled until the package layer binds transfers and authority.",
        "",
        '#include "util/types.h"',
        "",
        "namespace duetos::core::generated",
        "{",
        "",
        f"inline constexpr u32 kBootServiceManifestGeneratorVersion = {GENERATOR_VERSION};",
        f"inline constexpr bool kBootServiceManifestArtifactsResolved = {artifacts_resolved_literal};",
        "inline constexpr bool kBootServiceManifestActivationReady = false;",
        f"inline constexpr u64 kBootServiceManifestIdentity = 0x{manifest.manifest_identity:016X}ULL;",
        f"inline constexpr u64 kBootServiceManifestSignerIdentity = 0x{manifest.signer_identity:016X}ULL;",
        f"inline constexpr u64 kBootServiceManifestProfileIdentity = 0x{manifest.profile_identity:016X}ULL;",
        f"inline constexpr u32 kBootServiceManifestSize = {len(wire)};",
        f"inline constexpr u16 kBootServiceManifestServiceCount = {len(manifest.services)};",
        f"inline constexpr u16 kBootServiceManifestDependencyCount = {manifest.dependency_count};",
        "// clang-format off",
        f'inline constexpr char kBootServiceManifestSha256Hex[] = "{digest.hex()}";',
        "inline constexpr u8 kBootServiceManifestSha256[32] = {",
    ]
    for offset in range(0, len(digest), 12):
        chunk = digest[offset : offset + 12]
        lines.append("    " + ", ".join(f"0x{value:02X}" for value in chunk) + ",")
    lines.extend(["};", "", "alignas(8) inline constexpr u8 kBootServiceManifestBytes[] = {"])
    for offset in range(0, len(wire), 12):
        chunk = wire[offset : offset + 12]
        lines.append("    " + ", ".join(f"0x{value:02X}" for value in chunk) + ",")
    lines.extend(
        [
            "};",
            "// clang-format on",
            "",
            "static_assert(sizeof(kBootServiceManifestBytes) == kBootServiceManifestSize);",
            "static_assert(sizeof(kBootServiceManifestSha256) == 32);",
            "",
            "} // namespace duetos::core::generated",
            "",
        ]
    )
    return "\n".join(lines)


def _append_byte_array(lines: list[str], declaration: str, content: bytes) -> None:
    lines.append(declaration)
    for offset in range(0, len(content), 12):
        chunk = content[offset : offset + 12]
        lines.append("    " + ", ".join(f"0x{value:02X}" for value in chunk) + ",")
    lines.append("};")


def render_package_header(
    manifest: Manifest,
    wire: bytes,
    source_label: str,
    authority: AuthorityPolicy | None = None,
) -> str:
    if not manifest.artifacts_resolved:
        raise ManifestError("package header requires resolved artifacts")
    if any(service.artifact_bytes is None for service in manifest.services):
        raise ManifestError("package header requires exact bytes for every service artifact")

    total_artifact_bytes = sum(len(service.artifact_bytes or b"") for service in manifest.services)
    if total_artifact_bytes > MAX_EMBEDDED_PACKAGE_BYTES:
        raise ManifestError(
            f"embedded artifact package exceeds {MAX_EMBEDDED_PACKAGE_BYTES} bytes"
        )
    manifest_digest = hashlib.sha256(wire).digest()
    lines = [
        "#pragma once",
        "",
        "// Generated by tools/build/gen-service-manifest.py; do not edit.",
        f"// Source: {source_label}",
        "// This header binds manifest transfer references to exact build bytes.",
        "// A separately configured authenticated-kernel-image authority may bind",
        "// the manifest hash/extent, but sealed serviced/execd bootstrap plans and",
        "// activation remain absent.",
        "",
        '#include "core/service_object_package.h"',
        "",
        "namespace duetos::core::generated",
        "{",
        "",
        f"inline constexpr u32 kBootServicePackageGeneratorVersion = {GENERATOR_VERSION};",
        "inline constexpr bool kBootServicePackageArtifactsResolved = true;",
        "inline constexpr bool kBootServicePackageAuthorityBound = "
        + ("true;" if authority is not None else "false;"),
        "inline constexpr bool kBootServicePackageBootstrapPlansBound = false;",
        "inline constexpr bool kBootServicePackageActivationReady = false;",
        f"inline constexpr u32 kBootServicePackageManifestSize = {len(wire)};",
        f"inline constexpr u32 kBootServicePackageArtifactCount = {len(manifest.services)};",
        f"inline constexpr u64 kBootServicePackageTotalArtifactBytes = {total_artifact_bytes}ULL;",
        f'inline constexpr char kBootServicePackageManifestSha256Hex[] = "{manifest_digest.hex()}";',
        "",
        "// clang-format off",
    ]
    _append_byte_array(
        lines,
        "alignas(8) inline constexpr u8 kBootServicePackageManifestBytes[] = {",
        wire,
    )
    lines.append("")

    if authority is not None:
        lines.extend(
            [
                "inline constexpr ServiceManifestAuthoritySnapshotV1 "
                "kBootServicePackageManifestAuthority = {",
                f"    0x{authority.authority_identity:016X}ULL,",
                f"    0x{authority.manifest_identity:016X}ULL,",
                f"    0x{authority.signer_identity:016X}ULL,",
                f"    0x{authority.profile_identity:016X}ULL,",
                "    ::duetos::loader::Hash256{{",
            ]
        )
        for offset in range(0, len(manifest_digest), 12):
            chunk = manifest_digest[offset : offset + 12]
            lines.append("        " + ", ".join(f"0x{value:02X}" for value in chunk) + ",")
        lines.extend(
            [
                "    }},",
                f"    {len(wire)}ULL,",
                f"    0x{authority.capability_mask:016X}ULL,",
                f"    0x{authority.immutable_policy_mask:016X}ULL,",
                f"    {authority.max_frame_budget_pages}ULL,",
                f"    {authority.max_tick_budget}ULL,",
                f"    0x{authority.service_kind_mask:08X}U,",
                f"    0x{authority.resource_profile_mask:08X}U,",
                f"    {authority.max_section_objects}U,",
                f"    {authority.max_section_pages}U,",
                f"    {authority.max_services}U,",
                f"    {authority.max_dependencies}U,",
                "    kServiceManifestAuthoritySealed,",
                "    0ULL,",
                "};",
                "",
            ]
        )

    for service in manifest.services:
        assert service.artifact_bytes is not None
        symbol = f"kBootServiceArtifactRef{service.transfer_ref:08X}Bytes"
        lines.extend(
            [
                f"// service={service.name} source={service.content_source}",
                f"// sha256={service.content_hash.hex()}",
            ]
        )
        _append_byte_array(
            lines,
            f"alignas(8) inline constexpr u8 {symbol}[] = {{",
            service.artifact_bytes,
        )
        lines.append("")

    lines.append(
        "inline constexpr ServiceExecutableObjectDefinitionV1 "
        "kBootServicePackageExecutableObjects[] = {"
    )
    for service in manifest.services:
        symbol = f"kBootServiceArtifactRef{service.transfer_ref:08X}Bytes"
        lines.extend(
            [
                "    {",
                f"        {service.transfer_ref}U,",
                f"        {service.immutable_policy_selector}U,",
                f"        {symbol},",
                f"        sizeof({symbol}),",
                "        kServiceObjectDefinitionSealed,",
                "        0U,",
                "    },",
            ]
        )
    lines.extend(["};", ""])
    if authority is not None:
        lines.extend(
            [
                "inline constexpr ServiceObjectPackageDefinitionV1 kBootServicePackageDefinition = {",
                "    kBootServicePackageManifestBytes,",
                "    sizeof(kBootServicePackageManifestBytes),",
                "    &kBootServicePackageManifestAuthority,",
                "    kBootServicePackageExecutableObjects,",
                "    kBootServicePackageArtifactCount,",
                "    0U,",
                "};",
                "",
            ]
        )
    lines.extend(
        [
            "// clang-format on",
            "",
            "static_assert(sizeof(kBootServicePackageManifestBytes) ==",
            "              kBootServicePackageManifestSize);",
            "static_assert(sizeof(kBootServicePackageExecutableObjects) /",
            "                  sizeof(kBootServicePackageExecutableObjects[0]) ==",
            "              kBootServicePackageArtifactCount);",
            "static_assert(kBootServicePackageAuthorityBound);"
            if authority is not None
            else "static_assert(!kBootServicePackageAuthorityBound);",
            "static_assert(!kBootServicePackageBootstrapPlansBound);",
            "static_assert(!kBootServicePackageActivationReady);",
            "",
            "} // namespace duetos::core::generated",
            "",
        ]
    )
    return "\n".join(lines)


def parse_artifact_mappings(values: Iterable[str]) -> dict[str, str]:
    mappings: dict[str, str] = {}
    relative_paths: set[str] = set()
    for value in values:
        if value.count("=") != 1:
            raise ManifestError("artifact-map: expected SERVICE=RELATIVE/PATH")
        name, relative_path = value.split("=", maxsplit=1)
        if not NAME_RE.fullmatch(name):
            raise ManifestError(f"artifact-map: invalid service name {name!r}")
        if name in mappings:
            raise ManifestError(f"artifact-map: duplicate service {name!r}")
        canonical_relative_path = _canonical_artifact_map_path(
            relative_path, f"artifact-map[{name!r}]"
        )
        if canonical_relative_path in relative_paths:
            raise ManifestError(
                f"artifact-map[{name!r}]: duplicate artifact path {canonical_relative_path!r}"
            )
        relative_paths.add(canonical_relative_path)
        mappings[name] = canonical_relative_path
    return mappings


def _source_label(path: Path) -> str:
    repo_root = Path(__file__).resolve().parents[2]
    try:
        label = path.resolve().relative_to(repo_root).as_posix()
    except (OSError, RuntimeError, ValueError):
        label = path.name
    if not SOURCE_LABEL_RE.fullmatch(label):
        return "external-input"
    return label


def _write_or_check(path: Path, data: bytes, check: bool) -> None:
    if check:
        try:
            with path.open("rb") as current:
                if os.fstat(current.fileno()).st_size != len(data):
                    raise ManifestError(f"generated output is stale: {path}")
                expected = memoryview(data)
                offset = 0
                while chunk := current.read(1024 * 1024):
                    if chunk != expected[offset : offset + len(chunk)]:
                        raise ManifestError(f"generated output is stale: {path}")
                    offset += len(chunk)
        except OSError as error:
            raise ManifestError(f"generated output missing: {path}: {error}") from error
        if offset != len(data):
            raise ManifestError(f"generated output is stale: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(handle, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="canonical TOML source")
    parser.add_argument("--header", type=Path, help="generated C++ data header")
    parser.add_argument("--binary", type=Path, help="optional raw ServiceManifest v1 artifact")
    parser.add_argument("--normalized", type=Path, help="optional normalized JSON audit dump")
    parser.add_argument(
        "--package-header",
        type=Path,
        help="optional exact manifest/executable byte package header",
    )
    parser.add_argument(
        "--authority",
        type=Path,
        help="separate authenticated-kernel-image authority policy for the package header",
    )
    parser.add_argument(
        "--artifact-root",
        type=Path,
        help="bounded root for explicit build-artifact mappings",
    )
    parser.add_argument(
        "--artifact-map",
        action="append",
        default=[],
        metavar="SERVICE=RELATIVE/PATH",
        help="bind one manifest service to a file strictly below --artifact-root",
    )
    parser.add_argument("--check", action="store_true", help="verify outputs instead of writing them")
    args = parser.parse_args(argv)
    if (
        args.header is None
        and args.binary is None
        and args.normalized is None
        and args.package_header is None
    ):
        parser.error(
            "at least one output (--header, --binary, --normalized, or --package-header) is required"
        )

    try:
        if args.authority is not None and args.package_header is None:
            raise ManifestError("authority requires --package-header")
        mappings = parse_artifact_mappings(args.artifact_map)
        mapping_requested = args.artifact_root is not None or bool(args.artifact_map)
        if (args.artifact_root is None) != (not args.artifact_map):
            raise ManifestError("artifact-root and at least one artifact-map must be supplied together")
        manifest = load_manifest(
            args.input,
            artifact_root=args.artifact_root if mapping_requested else None,
            artifact_mappings=mappings if mapping_requested else None,
            retain_artifact_bytes=args.package_header is not None,
        )
        wire = encode_manifest(manifest)
        authority = load_authority(args.authority, manifest) if args.authority is not None else None
        header_bytes = (
            render_header(manifest, wire, _source_label(args.input)).encode("ascii")
            if args.header is not None
            else None
        )
        normalized_bytes = (
            normalized_json(manifest, wire, authority).encode("ascii")
            if args.normalized is not None
            else None
        )
        package_header_bytes = (
            render_package_header(manifest, wire, _source_label(args.input), authority).encode("ascii")
            if args.package_header is not None
            else None
        )
        if args.header is not None:
            assert header_bytes is not None
            _write_or_check(args.header, header_bytes, args.check)
        if args.binary is not None:
            _write_or_check(args.binary, wire, args.check)
        if args.normalized is not None:
            assert normalized_bytes is not None
            _write_or_check(args.normalized, normalized_bytes, args.check)
        if args.package_header is not None:
            assert package_header_bytes is not None
            _write_or_check(args.package_header, package_header_bytes, args.check)
    except ManifestError as error:
        print(f"gen-service-manifest: {error}", file=sys.stderr)
        return 2

    action = "verified" if args.check else "generated"
    package_state = "artifact-backed" if manifest.artifacts_resolved else "staged-artifacts"
    authority_state = "authority-bound" if authority is not None else "authority-unbound"
    print(
        f"gen-service-manifest: {action} {len(wire)} bytes, sha256={hashlib.sha256(wire).hexdigest()} "
        f"({len(manifest.services)} services, {manifest.dependency_count} dependencies, "
        f"{package_state}/{authority_state})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
