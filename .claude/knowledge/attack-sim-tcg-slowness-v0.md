# Slow boot under TCG — root cause + fix

**Type:** Issue + Pattern + Decision
**Status:** Active — fix landed; per-attack slowness in `attack_sim` is a separate, smaller problem (untouched in this slice)
**Last updated:** 2026-05-03

## Symptom

A debug build with `-DDUETOS_ATTACK_SIM=ON` took 10+ minutes of
wall-clock time before the attack-simulation suite finished
(versus the user's expectation of "a few minutes" for prior dev
boots).

## Root cause

Two recent commits added work-per-boot that is cheap on bare metal
but pathological under QEMU TCG without `/dev/kvm`:

| Commit | Cost per boot |
|--------|---------------|
| `af0a3e9 security/auth: replace FNV/64 password hash with PBKDF2-HMAC-SHA256` | 2× `PasswordHashCreate(100 000 iterations)` for the `admin` + `guest` seed (line `kernel/security/auth.cpp:275-277`) |
| `e81cbf9 security/auth: add boot-time AuthBruteForceProbe (adversarial check)` | 8× `AuthVerify(...)` — each evaluating `PBKDF2(100 000)` against the seeded admin record |

Each PBKDF2-HMAC-SHA256(100 000) means 100 000 SHA-256 rounds. The
kernel is built with `-mno-sse -mno-mmx -mno-80387` (no SIMD, no
FPU), and TCG without KVM interprets every x86 instruction. The
combination cost is ~3-7 wall-seconds per PBKDF2 — so the seed +
brute-force probe alone burned **30-60 wall-seconds** on every
boot.

Confirmed by tracing kernel-time (`[t=…ms]`) timestamps before/
after the fix: kernel-time-to-`[boot] All subsystems online`
dropped from 82.4 s to 21.2 s, a 4× speedup that lines up exactly
with skipping the heavy crypto.

## Fix

Two surgical edits, both gated on `arch::IsEmulator()` so bare
metal still gets full security coverage:

1. **`kernel/security/password_hash.{h,cpp}`** — added
   `kPasswordEmulatorIterations = 1 000` plus
   `PasswordDefaultIterations()` which returns `1 000` under any
   VMM, `100 000` on bare metal. `PasswordHashCreate` now consults
   this. The seeded admin/guest accounts are well-known
   placeholders, so the security tradeoff is meaningless on a
   dev VM.
2. **`kernel/security/auth_pentest.cpp`** — `AuthBruteForceProbe`
   short-circuits at entry on `IsEmulator()` with an informational
   `=== brute-force probe SKIPPED — running under emulator ===`
   log line. Mirrors the gating already used by
   `net::NetSmokeTestStart` (kernel/net/net_smoke.cpp:308) for
   the same reason (boot delay).

## Measured improvement

Same QEMU TCG host, no other changes:

| Marker | Before | After |
|--------|------:|------:|
| Kernel time at `[boot] All subsystems online` | 82.4 s | 21.2 s |
| Wall-clock budget to reach the suite | ~10 min | ~70 s |
| Attack-sim entries reachable in 5 min wall-clock | 6 | 10 |

(Under KVM, both versions take the same fast wall-clock — the
slowdown was purely a TCG-without-SIMD cost.)

## What didn't move

The remaining per-attack wall-clock cost (~30 s per `attacksim`
entry under TCG) is dominated by `runtime_checker`'s
`CheckBootSectors` re-reading every block device's LBA 0/1 on
every scan, which RunAttack invokes twice per attack. That's a
separate issue:

- The bootkit attack's restore writes the original byte back, but
  the heal path appears to re-baseline against the post-restore
  state, so subsequent scans still log `boot sector modified`
  drift on every poll. Visible in the `[health] boot sector
  modified` repetition between attack lines.
- Fixing requires either (a) suppressing the rescan during
  RunAttack's snapshot/scan/restore window, or (b) reordering the
  bootkit attack so it runs LAST (its escalation to `blockguard
  Deny` then doesn't poison sibling attacks). Neither was taken
  in this slice.

For algorithmic verification of the gap-fix attack, the hosted
unit test (`tests/host/test_text_hash.cpp`) sidesteps both costs
entirely — runs in 10 ms.

## Pattern: emulator-fast crypto for boot self-tests

`arch::IsEmulator()` is the existing gate for "skip workloads
that hurt boot time on QEMU." Use it for any boot-time CPU-bound
crypto path that has no security value on a dev VM. Existing
users:

- `kernel/net/net_smoke.cpp:308` — skip the live-internet probe
  on emulator (DHCP/DNS/TCP timeouts would burn ~15 s).
- `kernel/proc/ring3_smoke.cpp:2238,2818` — relax PE-image
  smoke essentialness on emulator.
- `kernel/fs/fat32_selftest.cpp:67` — skip a slow path-walk
  fixture on emulator.
- `kernel/security/auth_pentest.cpp` (new) — skip the brute-force
  probe on emulator.
- `kernel/security/password_hash.cpp` (new) — emulator-fast
  PBKDF2 iteration count.

If a future commit adds a >100 ms-on-bare-metal CPU-bound boot
self-test, run the same calculus: under TCG without SIMD it'll be
multiple wall-seconds — gate it on `IsEmulator()` unless the
coverage is uniquely valuable on emulator.
