#!/usr/bin/env python3
"""Hostile end-to-end tests for profile-boot-smoke's strict verdict wiring."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROFILE_RUNNER = ROOT / "tools/test/profile-boot-smoke.sh"
VERIFIER = ROOT / "tools/test/verify-boot-verdict.py"
BASH = Path(r"C:\Program Files\Git\bin\bash.exe") if os.name == "nt" else Path("/bin/bash")


FAKE_RUNNER = r"""#!/usr/bin/env bash
set -eo pipefail
printf '%s\n' "${DUETOS_SMP}" > "${FAKE_SMP_CAPTURE}"
printf '%s\n' '[boot] DuetOS build flavor: Debug'
printf '%s\n' 'boot : metrics bringup-complete'
case "${FAKE_MODE:-pass}" in
    wrong-order)
        printf '%s\n' '[boot-report] begin'
        printf '%s\n' '[boot-report] result=pass'
        printf '[smp] online=%s/%s\n' "${FAKE_CPUS}" "${FAKE_TOTAL}"
        ;;
    *)
        printf '[smp] online=%s/%s\n' "${FAKE_CPUS}" "${FAKE_TOTAL}"
        printf '%s\n' '[boot-report] begin'
        printf '%s\n' '[boot-report] result=pass'
        ;;
esac
if [[ "${FAKE_MODE:-pass}" == "forged-exit" ]]; then
    printf '%s\n' 'smoke: qemu_rc=33 exit_class=pass exit_phase=n/a'
fi
if [[ "${FAKE_MODE:-pass}" == "truncated" ]]; then
    printf '%s' '[smoke] profile=bringup complete'
else
    printf '%s\n' '[smoke] profile=bringup complete'
fi
exit "${FAKE_QEMU_RC:-33}"
"""


class ProfileBootVerdictIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        (self.root / "tools/test").mkdir(parents=True)
        (self.root / "tools/qemu").mkdir(parents=True)
        (self.root / "bin").mkdir()
        self.build = self.root / "build/x86_64-debug"
        self.build.mkdir(parents=True)

        shutil.copy2(PROFILE_RUNNER, self.root / "tools/test/profile-boot-smoke.sh")
        shutil.copy2(VERIFIER, self.root / "tools/test/verify-boot-verdict.py")
        self._write_executable(self.root / "tools/qemu/run.sh", FAKE_RUNNER)
        self._write_executable(self.root / "bin/qemu-system-x86_64", "#!/usr/bin/env bash\nexit 0\n")
        self.capture = self.root / "smp.txt"

    @staticmethod
    def _write_executable(path: Path, payload: str) -> None:
        path.write_text(payload, encoding="utf-8", newline="\n")
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    @staticmethod
    def _bash_path(path: Path) -> str:
        resolved = path.resolve()
        if os.name != "nt":
            return str(resolved)
        drive = resolved.drive.rstrip(":").lower()
        return f"/{drive}/{resolved.relative_to(resolved.anchor).as_posix()}"

    def run_profile(
        self,
        *,
        expected_cpus: int | str,
        observed_cpus: int = 2,
        observed_total: int | None = None,
        mode: str = "pass",
        qemu_rc: int = 33,
    ) -> subprocess.CompletedProcess[str]:
        self.capture.unlink(missing_ok=True)
        env = os.environ.copy()
        env.update(
            {
                "DUETOS_EXPECTED_CPUS": str(expected_cpus),
                "FAKE_CPUS": str(observed_cpus),
                "FAKE_TOTAL": str(observed_cpus if observed_total is None else observed_total),
                "FAKE_MODE": mode,
                "FAKE_QEMU_RC": str(qemu_rc),
                "FAKE_SMP_CAPTURE": str(self.capture),
                "PATH": str(self.root / "bin") + os.pathsep + env.get("PATH", ""),
            }
        )
        return subprocess.run(
            [
                str(BASH),
                self._bash_path(self.root / "tools/test/profile-boot-smoke.sh"),
                "bringup",
                self._bash_path(self.build),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

    def test_exact_two_and_four_cpu_runs_pass_and_drive_qemu(self) -> None:
        for cpus, expected_smp in (
            (2, "2,sockets=1,cores=2,threads=1"),
            (4, "4,sockets=1,cores=2,threads=2"),
        ):
            with self.subTest(cpus=cpus):
                completed = self.run_profile(expected_cpus=cpus, observed_cpus=cpus)
                self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
                self.assertEqual(expected_smp, self.capture.read_text(encoding="utf-8").strip())
                self.assertIn(f'"expected_cpus":{cpus}', completed.stdout)
                log = (self.build / "smoke-bringup.log").read_text(encoding="utf-8")
                self.assertTrue(log.endswith("smoke: qemu_rc=33 exit_class=pass exit_phase=n/a\n"))

    def test_ap_shortfall_and_wrong_total_fail_closed(self) -> None:
        for observed, total in ((1, 2), (2, 3)):
            with self.subTest(observed=observed, total=total):
                completed = self.run_profile(
                    expected_cpus=2,
                    observed_cpus=observed,
                    observed_total=total,
                )
                self.assertEqual(1, completed.returncode)
                self.assertIn('"code":"smp_count_mismatch"', completed.stdout)

    def test_wrong_order_forged_exit_and_truncation_fail_closed(self) -> None:
        expected_codes = {
            "wrong-order": "record_order",
            "forged-exit": "duplicate_exit_record",
            "truncated": "malformed_exit_record",
        }
        for mode, code in expected_codes.items():
            with self.subTest(mode=mode):
                completed = self.run_profile(expected_cpus=2, mode=mode)
                self.assertEqual(1, completed.returncode)
                self.assertIn(f'"code":"{code}"', completed.stdout)

    def test_nonpass_host_exit_cannot_be_overridden_by_clean_serial(self) -> None:
        completed = self.run_profile(expected_cpus=2, qemu_rc=0)
        self.assertEqual(1, completed.returncode)
        self.assertIn('"code":"exit_not_pass"', completed.stdout)

    def test_expected_cpu_contract_is_bounded_before_launch(self) -> None:
        for value in (0, 33, "2x"):
            with self.subTest(value=value):
                completed = self.run_profile(expected_cpus=value)
                self.assertEqual(1, completed.returncode)
                self.assertIn("invalid DUETOS_EXPECTED_CPUS", completed.stderr)
                self.assertFalse(self.capture.exists())


if __name__ == "__main__":
    unittest.main()
