#!/usr/bin/env python3
"""Hostile structural guardrails for exact Process security ownership.

The hosted Credential and AuthorizationContext suites prove service behavior.
This companion check prevents Process and its bounded OS-wide adapters from
reintroducing a mutable authority mirror, inheriting leases, or releasing an
exact security owner before runtime enforcement users have drained.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def code_only(source: str) -> str:
    """Blank C/C++ comments and literals while retaining source offsets."""
    masked = list(source)

    def blank(begin: int, end: int) -> None:
        for offset in range(begin, end):
            if masked[offset] not in "\r\n":
                masked[offset] = " "

    index = 0
    while index < len(source):
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            if end < 0:
                end = len(source)
            blank(index, end)
            index = end
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end < 0:
                raise AssertionError("unterminated block comment")
            end += 2
            blank(index, end)
            index = end
            continue

        raw_prefix = next(
            (prefix for prefix in ('u8R"', 'uR"', 'UR"', 'LR"', 'R"') if source.startswith(prefix, index)),
            None,
        )
        if raw_prefix is not None:
            delimiter_begin = index + len(raw_prefix)
            open_paren = source.find("(", delimiter_begin, delimiter_begin + 17)
            if open_paren >= 0:
                delimiter = source[delimiter_begin:open_paren]
                if not re.search(r"[\s\\()]", delimiter):
                    terminator = ")" + delimiter + '"'
                    end = source.find(terminator, open_paren + 1)
                    if end < 0:
                        raise AssertionError("unterminated raw string")
                    end += len(terminator)
                    blank(index, end)
                    index = end
                    continue

        # C++ digit separators use apostrophes inside numeric tokens; they are
        # not character literals (for example 1'000 or 0xFFFF'FFFF).
        if (
            source[index] == "'"
            and index > 0
            and index + 1 < len(source)
            and source[index - 1].isalnum()
            and source[index + 1].isalnum()
        ):
            index += 1
            continue

        if source[index] in "\"'":
            quote = source[index]
            end = index + 1
            while end < len(source):
                if source[end] == "\\":
                    end += 2
                    continue
                if source[end] == quote:
                    end += 1
                    break
                end += 1
            else:
                raise AssertionError("unterminated quoted literal")
            blank(index, end)
            index = end
            continue
        index += 1
    return "".join(masked)


def matching_delimiter(source: str, opening: int, left: str = "{", right: str = "}") -> int:
    if opening < 0 or source[opening] != left:
        raise AssertionError(f"missing opening delimiter {left!r}")
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == left:
            depth += 1
        elif source[index] == right:
            depth -= 1
            if depth == 0:
                return index
    raise AssertionError(f"unterminated {left}{right} region")


def function_body(source: str, signature: str) -> str:
    code = code_only(source)
    for match in re.finditer(signature + r"\s*\(", code):
        opening_paren = code.find("(", match.start())
        closing_paren = matching_delimiter(code, opening_paren, "(", ")")
        opening_brace = code.find("{", closing_paren + 1)
        declaration_end = code.find(";", closing_paren + 1)
        if declaration_end >= 0 and (opening_brace < 0 or declaration_end < opening_brace):
            continue
        if opening_brace >= 0:
            closing_brace = matching_delimiter(code, opening_brace)
            return code[opening_brace + 1 : closing_brace]
    raise AssertionError(f"missing function definition: {signature}")


def type_body(source: str, declaration: str) -> str:
    code = code_only(source)
    match = re.search(declaration + r"[^;{]*\{", code)
    if match is None:
        raise AssertionError(f"missing type: {declaration}")
    opening = code.find("{", match.start())
    return code[opening + 1 : matching_delimiter(code, opening)]


def assert_ordered(test: unittest.TestCase, source: str, *tokens: str) -> None:
    cursor = -1
    for token in tokens:
        found = source.find(token, cursor + 1)
        test.assertGreater(found, cursor, f"missing or out-of-order token: {token}")
        cursor = found


class ParserHostileTests(unittest.TestCase):
    def test_comments_strings_and_raw_literals_cannot_satisfy_contracts(self) -> None:
        hostile = r'''
// CredentialKey credentials;
/* AuthorizationDeriveForSpawn(parent, now, 0, caps, ceiling, budget, profile, out); */
const char* normal = "ReleaseProcessSecurityOwners(fake);";
const char* raw = u8R"tag(ProcessChargeExecutionTicks(fake, 1); // } {)tag";
int visible = 7;
'''
        visible = code_only(hostile)
        self.assertNotIn("CredentialKey credentials", visible)
        self.assertNotIn("AuthorizationDeriveForSpawn", visible)
        self.assertNotIn("ReleaseProcessSecurityOwners", visible)
        self.assertNotIn("ProcessChargeExecutionTicks", visible)
        self.assertIn("int visible = 7;", visible)

    def test_function_slicer_ignores_prototype_and_literal_decoy(self) -> None:
        hostile = r'''
bool Probe(int);
const char* decoy = "bool Probe(int) { return false; }";
bool Probe(int value) { return value != 0; }
bool After() { return false; }
'''
        body = function_body(hostile, r"bool\s+Probe")
        self.assertIn("return value != 0;", body)
        self.assertNotIn("bool After", body)


class ProcessAuthorityWiringContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.process_h = read("kernel/proc/process.h")
        cls.process_cpp = read("kernel/proc/process.cpp")
        cls.credentials_cpp = read("kernel/proc/credentials.cpp")
        cls.authorization_cpp = read("kernel/proc/authorization_context.cpp")
        cls.sched_cpp = read("kernel/sched/sched.cpp")

    def test_process_owns_exact_keys_and_no_legacy_authority_mirror(self) -> None:
        process = type_body(self.process_h, r"struct\s+Process\b")
        self.assertRegex(process, r"\bCredentialKey\s+credentials\s*;")
        self.assertRegex(process, r"\bAuthorizationContextKey\s+authorization\s*;")
        for retired in (
            "cap_lock",
            "caps",
            "cap_ceiling",
            "cap_leases",
            "cap_lease_generation",
            "cap_lease_deadline_ns",
            "tick_budget",
            "ticks_used",
            "sandbox_denials",
            "sandbox_kill_flagged",
            "fs_write_bytes_total",
            "fs_write_window_bytes",
            "fs_write_window_start_tick",
        ):
            with self.subTest(retired=retired):
                self.assertNotRegex(process, rf"\b{retired}\b\s*(?:\[|;)")

    def test_credential_roots_are_fixed_kernel_policy_values(self) -> None:
        trusted_context = function_body(self.credentials_cpp, r"CredentialSecurityContext\s+TrustedRootContext")
        self.assertGreaterEqual(trusted_context.count("kCredentialCapabilityKnownMask"), 4)
        self.assertIn("Win32IntegrityLevel::System", trusted_context)

        trusted_create = function_body(
            self.credentials_cpp, r"bool\s+CredentialAuthorityCreateTrustedRoot"
        )
        self.assertIn("CredentialAuthorityCreateTrusted(TrustedRootContext(), out_key)", trusted_create)

        nobody = function_body(self.credentials_cpp, r"bool\s+CredentialAuthorityCreateNobodySandbox")
        self.assertEqual(nobody.count("kCredentialNobodyId"), 2)
        self.assertIn("CredentialAuthorityCreateSandbox(nobody, out_key)", nobody)

        sandbox_context = function_body(self.credentials_cpp, r"CredentialSecurityContext\s+SandboxContext")
        self.assertIn("CredentialSecurityContext context{}", sandbox_context)
        self.assertIn("Win32IntegrityLevel::Low", sandbox_context)
        self.assertNotIn("capability_effective =", sandbox_context)
        self.assertNotIn("capability_permitted =", sandbox_context)

    def test_policy_thresholds_have_one_authorization_source(self) -> None:
        process = code_only(self.process_h)
        self.assertIn(
            "kSandboxDenialKillThreshold = kAuthorizationDenialThreshold",
            process,
        )
        self.assertIn(
            "kFsWriteWindowTicksByLevel = kAuthorizationFsWriteWindowTicks",
            process,
        )
        self.assertIn(
            "kFsWriteWindowByteCapByLevel = kAuthorizationFsWriteWindowByteCaps",
            process,
        )
        authorization = code_only(self.authorization_cpp)
        self.assertNotIn("kFsWriteWindowTicksByLevel", authorization)
        self.assertNotIn("kFsWriteWindowByteCapByLevel", authorization)

    def test_process_creation_retains_or_mints_exact_credentials_and_unwinds(self) -> None:
        create = function_body(self.process_cpp, r"Process\s*\*\s*ProcessCreate")
        assert_ordered(
            self,
            create,
            "p->resource_domain = resource_domain",
            "p->credentials = kInvalidCredentialKey",
            "CredentialRetain(spawn_parent->credentials)",
            "CredentialAuthorityCreateNobodySandbox(&p->credentials)",
            "CredentialAuthorityCreateTrustedRoot(&p->credentials)",
            "ReleaseProcessResourceDomainOwner(p",
            "p->authorization = kInvalidAuthorizationContextKey",
            "AuthorizationDeriveForSpawn(spawn_parent->authorization",
            "AuthorizationCreateSandbox(bounded_caps",
            "AuthorizationCreateTrusted(bounded_caps",
            "ReleaseProcessSecurityOwners(p",
            "ReleaseProcessResourceDomainOwner(p",
        )
        self.assertNotIn("CredentialAuthorityCreateTrusted(", create)
        self.assertNotIn("CredentialAuthorityCreateSandbox(", create)

        authorization_failure = create.index("if (!have_authorization)")
        pid_failure = create.index("if (process_identity == 0)")
        self.assertEqual(create[authorization_failure:pid_failure].count("ReleaseProcessSecurityOwners(p"), 1)
        self.assertEqual(create[authorization_failure:pid_failure].count("ReleaseProcessResourceDomainOwner(p"), 1)
        self.assertEqual(create[pid_failure:].count("ReleaseProcessSecurityOwners(p"), 1)
        self.assertEqual(create[pid_failure:].count("ReleaseProcessResourceDomainOwner(p"), 1)

    def test_spawn_derivation_is_monotonic_independent_and_lease_free(self) -> None:
        derive = function_body(self.authorization_cpp, r"bool\s+AuthorizationDeriveForSpawn")
        for required in (
            "child_durable.bits & ~parent_row->durable_bits",
            "child_ceiling.bits & ~parent_row->ceiling_bits",
            "parent_row->provenance == AuthorizationLaunchProfile::Sandbox",
            "child_profile != AuthorizationLaunchProfile::Sandbox",
            "AllocateLocked(child_profile, child_durable.bits, child_ceiling.bits",
        ):
            self.assertIn(required, derive)
        self.assertNotIn("AuthorizationRetain", derive)
        self.assertNotIn("parent_row->lease_bits", derive)
        self.assertNotIn("parent_row->lease_deadline_ns", derive)

        allocate = function_body(self.authorization_cpp, r"AuthorizationContextKey\s+AllocateLocked")
        self.assertIn("row.lease_bits = 0", allocate)
        self.assertIn("row.lease_deadline_ns[index] = 0", allocate)
        self.assertIn("row.owner_references = 1", allocate)

    def test_process_adapters_have_one_authorization_source(self) -> None:
        required_calls = {
            r"CapSet\s+ProcessCapsSnapshot": "AuthorizationSnapshot",
            r"bool\s+ProcessCapsTrySnapshotNoExpire": "AuthorizationTrySnapshotNoExpire",
            r"bool\s+ProcessCapsGrant": "AuthorizationGrantDurable",
            r"bool\s+ProcessCapsGrantLease": "AuthorizationGrantLease",
            r"bool\s+ProcessCapsRevokeLease": "AuthorizationRevokeLease",
            r"CapSet\s+ProcessCapsDisableMask": "AuthorizationDisableMask",
            r"CapSet\s+ProcessCapsDropMask": "AuthorizationDropIrreversiblyWithPrevious",
            r"AuthorizationActionResult\s+ProcessChargeExecutionTicks": "AuthorizationChargeTick",
            r"u64\s+ProcessTicksUsedSnapshot": "ProcessInspectAuthorization",
            r"u64\s+ProcessSandboxDenialCountSnapshot": "ProcessInspectAuthorization",
            r"u64\s+RecordSandboxDenial": "AuthorizationRecordDenial",
            r"i32\s+RecordFsWriteCheckLevel": "AuthorizationRecordFsWrite",
        }
        for signature, call in required_calls.items():
            with self.subTest(signature=signature):
                self.assertIn(call, function_body(self.process_cpp, signature))

        capture = function_body(self.process_cpp, r"bool\s+ProcessCaptureSpawnAuthority")
        self.assertEqual(capture.count("ProcessInspectAuthorization"), 1)
        self.assertIn("snapshot.durable_bits", capture)
        self.assertIn("snapshot.effective_bits", capture)
        self.assertIn("snapshot.ceiling_bits", capture)

    def test_timer_paths_charge_authorization_without_direct_process_fields(self) -> None:
        sched = code_only(self.sched_cpp)
        self.assertGreaterEqual(sched.count("ProcessChargeExecutionTicks(proc, 1)"), 2)
        self.assertNotRegex(sched, r"proc\s*->\s*(?:tick_budget|ticks_used)\b")

    def test_runtime_drain_releases_security_then_resource_and_exit_has_no_owner(self) -> None:
        teardown = function_body(self.process_cpp, r"void\s+TeardownProcessRuntimeResources")
        assert_ordered(
            self,
            teardown,
            "HandleTableDrain(p->kobj_handles)",
            "LeakDetectorReportProcessExit(*p)",
            "ReleaseProcessSecurityOwners(p",
            "ReleaseProcessResourceDomainOwner(p",
        )
        release = function_body(self.process_cpp, r"void\s+ProcessRelease")
        exited = release[release.index("ProcessLifecycleState::Exited") :]
        self.assertIn("!CredentialKeyIsValid(p->credentials)", exited)
        self.assertIn("!AuthorizationContextKeyIsValid(p->authorization)", exited)

    def test_os_tree_has_no_direct_access_to_retired_process_security_fields(self) -> None:
        forbidden = re.compile(
            r"(?:->|\.)\s*(?:cap_lock|cap_ceiling|cap_leases|cap_lease_generation|"
            r"cap_lease_deadline_ns|sandbox_denials|sandbox_kill_flagged)\b|"
            r"->\s*(?:tick_budget|ticks_used|fs_write_bytes_total|fs_write_window_bytes|"
            r"fs_write_window_start_tick|fs_write_window_initialized|last_fs_write_tick|"
            r"fs_write_clock_initialized|fs_write_time_regressed|fs_write_threshold_latched)\b"
        )
        allowed = {
            ROOT / "kernel/proc/authorization_context.cpp",
            ROOT / "tests/host/test_authorization_context.cpp",
        }
        violations: list[str] = []
        for tree in (ROOT / "kernel", ROOT / "tests/host"):
            for path in tree.rglob("*"):
                if path.suffix not in {".cpp", ".h"} or path in allowed:
                    continue
                try:
                    code = code_only(path.read_text(encoding="utf-8"))
                except (AssertionError, UnicodeDecodeError) as error:
                    violations.append(f"{path.relative_to(ROOT)}: parser failure: {error}")
                    continue
                for match in forbidden.finditer(code):
                    token = re.sub(r"\s+", "", match.group(0))
                    # DbgProcessInfo is an output DTO. Its field name is
                    # intentionally ticks_used, but the value is supplied by
                    # ProcessTicksUsedSnapshot above rather than read from a
                    # Process owner.
                    if path == ROOT / "kernel/apps/dbg_core.cpp" and token == "->ticks_used":
                        continue
                    line = code.count("\n", 0, match.start()) + 1
                    violations.append(f"{path.relative_to(ROOT)}:{line}: {match.group(0).strip()}")
        self.assertEqual(violations, [], "direct authority mirror consumers remain:\n" + "\n".join(violations))

    def test_synthetic_enforcement_probes_own_explicit_contexts(self) -> None:
        for path in (
            "kernel/syscall/cap_gate.cpp",
            "kernel/security/broker.cpp",
            "kernel/security/grace.cpp",
            "kernel/security/attack_sim.cpp",
            "kernel/subsystems/win32/token_syscall.cpp",
        ):
            with self.subTest(path=path):
                code = code_only(read(path))
                self.assertIn("Authorization", code)
                self.assertNotRegex(code, r"(?:\.|->)\s*(?:cap_lock|caps|cap_ceiling|cap_leases)\s*=")


if __name__ == "__main__":
    unittest.main(verbosity=2)
