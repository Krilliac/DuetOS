# Function-branch NOP-patch attack — v0

**Type:** Observation + Decision + Pattern
**Status:** Active — attack landed, detection gap closed in the same slice
**Last updated:** 2026-05-03

## What it is

Adds a 17th entry to the kernel attacker-simulation suite
(`kernel/security/attack_sim.cpp`) that models the most surgical
kernel-rootkit move on the menu: **NOP out a single conditional
jump inside a cap-gate decision**.

The gated function still runs the cap test (the `test`/`cmp`
instruction is left intact, so flags are still set the same way) —
but the `jcc` that turns those flags into a deny path is gone, so
control unconditionally falls through into the success arm. Every
caller passes the gate, regardless of the cap they actually hold.

Real-world parallel: `kernel/syscall/syscall.cpp:458` reads

```cpp
if (!SyscallGate(num, dispatch_proc).has_value()) return -1;
```

which the compiler emits as a `test`+`jcc` pair downstream of the
`call SyscallGate` site. NOPing that two-byte short `jcc` would
turn the central capability gate into an unconditional accept on
every syscall — defeating the whole `kCap*` model regardless of
how correctly each handler honours its declared cap.

## How the probe is structured

The synthetic gated function is defined in a global asm block at
file scope so the probe owns the byte layout exactly:

```
AttackSimGatedAccess:
    test %rsi, %rdi
AttackSimGatedAccess_jcc:
    je  AttackSimGatedAccess_fail   ; 74 03  ← the patch site
    xor %eax, %eax                  ; 31 C0  (success arm: rc=0)
    ret                             ; C3
AttackSimGatedAccess_fail:
    mov $-1, %eax                   ; B8 FF FF FF FF
    ret                             ; C3
```

Three reasons for owning the bytes via inline asm rather than a C++
function:

1. **No compiler `cmov`.** GCC at `-O2`/`-O3` cheerfully collapses
   short `if (cond) return X; else return Y;` bodies into a `cmov`,
   which has no conditional jump to NOP. A real attacker would just
   look elsewhere — but for a deterministic test harness we need the
   branch to exist.
2. **Labeled patch site.** `AttackSimGatedAccess_jcc` is a real
   symbol; no opcode scanner, no scan heuristic, no cross-rebuild
   fragility.
3. **Predictable middle-`.text` placement.** The function lives in
   `attack_sim.cpp`'s `.text` slice, which links into the middle of
   the kernel image. That placement is the *interesting* one (see
   the gap finding below).

## The patch sequence

```
cli                                ; mask IRQs across the WP-clear window
mov  cr0, %r0; r0 &= ~CR0.WP       ; briefly mark .text writable
                                   ; (.text is RX in normal operation)
*p++ = 0x90                        ; NOP byte 0
*p++ = 0x90                        ; NOP byte 1
cpuid                              ; SDM Vol 3 §8.1.3 — serialize so the
                                   ; upcoming call sees the new bytes,
                                   ; not the prefetched old encoding
mov  cr0, %r0; r0 |= CR0.WP        ; restore .text RX
sti                                ; restore IRQs IFF rflags.IF was set
```

Verification that the bypass actually landed:

```
baseline_rc = AttackSimGatedAccess(0, 1)   ; expect -1 (gate denies)
... patch ...
post_rc     = AttackSimGatedAccess(0, 1)   ; expect 0  (bypass)
```

A paired baseline call BEFORE the patch is the honest anchor —
without it, "`post_rc == 0`" could be explained by an environmental
fluke. The probe logs both side by side.

## Red-team finding (originally surfaced, then closed in the same slice)

The first cut of `ComputeTextSpotHash` (kernel/diag/runtime_checker.cpp:801)
only FNV-1a hashed the **first 4 KiB and last 4 KiB** of `.text`. The
comment there was honest about the choice: full-text would take
~1 ms per scan, the spot hash takes ~2 µs and catches the boot-path
+ tail-end handler modifications that account for the 99% case.

The 1% case is the surgical attack this slice models. As measured
on a debug build:

- `_text_start = 0xffffffff8010a000`
- `_text_end   = 0xffffffff8022e000`
- text size    = ~1.14 MiB
- Patch site   = `0xffffffff801b8c03` → offset `0xAEC03` (~716 KiB)
- Spot windows = `[0, 4 KiB)` and `[text_size − 4 KiB, text_size)`

The patch lands ~700 KiB into a 1.14 MiB section. Outside both
windows. The pre-fix `CheckKernelText` could not see it.

### The fix (landed in this slice)

`runtime_checker.cpp` now keeps **two** baselines and checks both
on every scan:

- `g_baseline_text_spot_hash` — head + tail 4 KiB FNV-1a (existing,
  fast-path early warning, ~2 µs per scan).
- `g_baseline_text_full_hash` — entire `.text` FNV-1a (new, closes
  the middle-section gap, ~1 ms per scan on a 1.14 MiB section ≈
  0.02% scheduler overhead at the 5 s scan cadence).

`CheckKernelText` reports `KernelTextModified` if **either** drifts.
Three diagnostic log shapes distinguish the cases:

```
[health] kernel text drift: SPOT+FULL  (head/tail mod or wide rewrite)
[health] kernel text drift: SPOT-only  (head/tail .text byte changed)
[health] kernel text drift: FULL-only  (mid-.text byte changed; spot windows clean)
```

Boot-time baseline log gained a `text_full=…` field next to the
existing `text_spot=…` so an operator can confirm the second
baseline was captured.

### Expected outcome of this attack now

- **Bypass the gate** — `BYPASS LANDED` log line, `baseline_rc=-1`,
  `post_rc=0`. The patch itself still lands; the *defense* is the
  detector, not the inability of the attacker to write the bytes.
- **Detector fires** — `[health] kernel text drift: FULL-only …`
  serial line, `KernelTextModified` counter bumps, `RunAttack`
  reports `Pass`.

If a future regression silently turns the full-hash check off (e.g.
someone shortcuts `CheckKernelText` to "just check the spot hash
because that's faster"), this attack flips back to `FailNoDetect`
and the `BYPASS LANDED` log line stays — the suite re-surfaces the
gap loudly without anyone having to remember it was ever there.

## Wiring

- `kernel/security/attack_sim.cpp` — synthetic gated function
  (global asm), `AttackBranchNopPatch` / `RestoreBranchNopPatch`,
  `BranchPatchInSpotWindow` predicate, and one new entry in
  `kSpecs[]` (size grew 16 → 17; `kMaxAttackResults` already 24).
  `_text_end` extern declaration added next to the existing
  `_text_start` decl (so the in-spot-window predicate can run).
- `kernel/diag/runtime_checker.cpp` — `g_baseline_text_full_hash`,
  `ComputeTextFullHash`, `CheckKernelText` rewritten to consult
  both spot + full hashes and log the drift class. Baseline
  capture in `RuntimeCheckerInit` and serial summary in the boot
  banner both extended to carry the new value.

No header surface change. No new `HealthIssue` enum value (a
middle-`.text` modification is still a kernel-text modification —
the existing `KernelTextModified` issue is the right channel).

## Follow-on (still open)

The chosen fix is the cheaper of the two options on the table —
full FNV-1a every scan. The page-CRC alternative remains an
attractive future slice if the workload ever outgrows the ~1 ms
per scan budget:

- **Periodic page-CRC against the load-time digest.** At boot,
  capture a CRC32 per executable page in the kernel image. The
  runtime checker walks one page per scan (round-robin), comparing
  live CRC to the boot baseline. ~256 µs per scan; full coverage
  in `text_pages × 5 seconds` (~1 minute for a 1 MiB section at
  4 KiB pages). Bonus: pinpoints the modified page so the operator
  log can name it. Worth doing if either (a) `.text` grows past
  ~10 MiB and the per-scan cost crosses 10 ms, or (b) we want
  scan-to-scan deterministic latency rather than the current "1 ms
  every scan" model.

## Patterns this entry validates

- **Inline-asm-owned synthetic targets are the right shape for
  branch-level attack tests.** The compiler will optimize away every
  trivial C++ branch you try to give it. If you need a known opcode
  pattern at a known address, write the function yourself.
- **Honest reporting beats inflating coverage.** The suite was
  tempted to call `RuntimeCheckerBumpIssueCounter_ForTest` to make
  this entry `Pass` (matching the canary / persistence / stack-canary
  pattern). The slice deliberately doesn't, because the *whole point*
  is to surface the defense gap. Test-bump hooks are for self-harm
  avoidance (canary panics, persistence kills caller); they aren't
  for masking a missing detector.
- **Per-CPU code modification needs `cpuid` between writer and
  consumer.** SDM Vol 3 §8.1.3: the executing software must run a
  serializing instruction (CPUID is canonical) before the modified
  bytes are fetched. Without it, the prefetch queue can hold the
  old encoding across the patch and the next call returns the
  wrong answer. The existing `AttackKernelTextPatch` (boot-stub
  variant) gets away without it because the patched bytes are
  dormant for the rest of the session — never re-executed. This
  variant *immediately* re-enters the patched function, so the
  serializer is load-bearing.
