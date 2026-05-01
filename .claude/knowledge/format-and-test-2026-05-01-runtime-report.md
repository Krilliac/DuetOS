# Format + boot + test runtime report — 2026-05-01

**Last updated:** 2026-05-01
**Type:** Observation
**Status:** Active — follow-up inventory

## Description

Single-pass exercise: ran a full-tree `clang-format -i`, rebuilt both
release and debug presets, booted both in QEMU under
`tools/qemu/run.sh` (UEFI + OVMF), and recorded every compile-time
warning + every runtime warning/error emitted on the serial log.

The release build **stayed alive cleanly** for the full timeout (42 s
of heartbeats, no panic). The debug build (which has
`DUETOS_BOOT_SELFTESTS=ON`) **panics during boot** in
`CvtSelfTest()` before the smoke test's expected signatures appear,
which is why `ctest --output-on-failure` reports the boot smoke test
as failed.

This entry is purely an inventory — none of the items below are
fixed in the same commit. They are recorded so a follow-up session
can pick the highest-value thing to address first without
re-deriving the list.

## Format pass

Canonical command from `.claude/knowledge/clang-format.md`:

```bash
find kernel boot userland tests \
  \( -name '*.h' -o -name '*.hpp' -o -name '*.c' -o -name '*.cpp' \) \
  | xargs clang-format -i
```

Files in scope: 712. After the pass, **only one file changed**:

- `userland/apps/mini_browser/browser.c` — pointer-asterisk spacing
  (`const char *s` → `const char* s` and friends; 4 lines).

`clang-format --dry-run --Werror` after the pass exits 0. The single
diff matches the project's `.clang-format` (Allman, 4-space indent,
120-col, `PointerAlignment: Left`).

## Build summary

- `cmake --preset x86_64-release` + build: **OK** (757 targets,
  20 warnings).
- `cmake --preset x86_64-debug` + build: **OK** (same target count,
  same warning set; debug adds the smoke-test driver scripts).
- `cmake --preset host-tests` (separate project under `tests/host/`)
  + build + ctest: **2/2 PASS** (`result`, `string`).

### Compile-time warnings (43 unique sites, by category)

| Category (`-W...`) | Count | Hot spots |
|--------------------|-------|-----------|
| `shadow` | 19 | `kernel/syscall/syscall.cpp` (17 sites — all `Process* proc = CurrentProcess()` shadowing the file-scope `const Process* proc` at line 436); `kernel/diag/hexdump.cpp` (2 sites — locals shadowing namespace-anon globals) |
| `missing-field-initializers` | 5 | `kernel/drivers/video/theme.cpp` lines 106/166/229/559/615 — `font_kind` field absent from struct initializers |
| `unused-function` | 4 | `kernel/loader/pe_exports.cpp:43 LeU64`; `kernel/net/socket.cpp:29 IpEq`; `userland/apps/windowed_hello/hello.c:123 str_len`; `userland/libs/gdi32/gdi32.c:377 gdi32_ascii_len` |
| `unused-const-variable` | 3 | `kernel/subsystems/linux/syscall_async_io.cpp:74 kEFD_NONBLOCK`; `kernel/subsystems/linux/syscall_pipe.cpp:58 kEagain`; `kernel/subsystems/linux/syscall_socket.cpp:36 kEDestAddrReq` |
| `unused-parameter` | 3 | `kernel/drivers/net/iwlwifi_upload.cpp:131 n`; `kernel/subsystems/linux/keyrings.cpp:225 a5`; `userland/libs/kernel32/kernel32.c:3832 lpCurrentDirectory` |
| `unused-variable` | 2 | `kernel/drivers/gpu/cvt.cpp:201 v_back_porch`, `:205 v_total` (in `GenerateStandard`; computed but never read out — likely a hint about why the Standard-mode pixel-clock test is now mis-tuned, see runtime panic below) |
| `return-type` | 2 | `userland/apps/syscall_stress/hello.c:498`; `userland/apps/thread_stress/hello.c:117` — non-void function falls off the end without returning |
| `memset-transposed-args` | 1 | `kernel/util/string.cpp:108` — `memset(buf, 0xFF, 0)` is **intentional** (it asserts `n=0` is a no-op); compiler doesn't know. Either suppress with `(void)0` or move to a wrapper that passes the size through a `volatile`. |
| `comment` | 1 | `kernel/fs/file_route.cpp:9` — nested `/*` inside a block comment |

The full list lives in `/tmp/duetos-runtime-report/build-warns-sorted.txt`
during the session that produced it; the build re-derives it from
scratch on `--clean-first`. Treat this table as the durable summary.

These are warnings, not errors — the build is `-Wall -Wextra -Wpedantic`
without `-Werror` for the kernel TUs (CI may differ). None of them
block boot.

## Boot result — release preset

`DUETOS_PRESET=x86_64-release tools/qemu/run.sh` over a 60 s timeout:

- Boots through UEFI + OVMF, GRUB, multiboot2 handoff, long-mode
  trampoline, kernel main, all init phases.
- Reaches the kheartbeat loop and emits ~85 heartbeats (every ~500 ms)
  before QEMU is killed by the timeout.
- `health_last_scan_issues = 0`, `health_issues_total = 0`,
  `fault_domains_count = 11` (all registered domains stable, no
  ESCALATE).
- **No panic, no triple fault, no `[E]`-level errors** other than
  the deliberate `core/klog : error-level sanity line` (a
  klog-channel smoke probe that always fires).

Conclusion: the **kernel itself stays alive** cleanly under the
release preset. Everything below is either a self-test failure
(triggered only by `DUETOS_BOOT_SELFTESTS=ON`) or a soft warning
that the boot path classifies as expected.

## Boot result — debug preset (selftests on)

Panics at `t = 414.117 ms`:

```
[panic] drivers/gpu/cvt: CVT pixel clock out of range
  rip       : 0xffffffff80144671  [duetos::drivers::gpu::CvtSelfTest()+0x231 (kernel/drivers/gpu/cvt.cpp:271)]
  task      : kboot#1
```

Source site: `kernel/drivers/gpu/cvt.cpp:319-324`:

```cpp
const u64 lo = static_cast<u64>(c.expected_pclk_khz) * (100 - c.expected_pclk_tol_pct) / 100;
const u64 hi = static_cast<u64>(c.expected_pclk_khz) * (100 + c.expected_pclk_tol_pct) / 100;
if (t.pixel_clock_khz < lo || t.pixel_clock_khz > hi)
{
    ::duetos::drivers::video::ConsoleWrite("[selftest] CVT ");
    ::duetos::drivers::video::ConsoleWrite(c.tag);
    ConsoleWriteln(": pixel clock outside ±tolerance");
    ::duetos::core::Panic("drivers/gpu/cvt", "CVT pixel clock out of range");
}
```

The pre-panic `ConsoleWrite` of "[selftest] CVT <tag>: ..." routes
through the framebuffer console, not COM1, so the failing case tag
is **not visible in the serial log**. Ways to identify it:

1. Add a `klog::Warn(...)` (which goes to serial) alongside the
   ConsoleWrite, dumping `c.tag`, `t.pixel_clock_khz`, `lo`, `hi`
   for the failing case.
2. Or run with `DUETOS_DISPLAY=gtk` and read the framebuffer.

Strong suspect: the table at `cvt.cpp:286-299` has six cases. The
two `[-Wunused-variable]` warnings on `cvt.cpp:201,205`
(`v_back_porch`, `v_total` in `GenerateStandard`) hint that the
Standard-mode path was refactored and the porch/total math was
left in but disconnected from the pixel-clock formula — i.e.
the `1280x1024@60 STD` case (the only Standard-mode case in the
table) is the most likely failure. Worth checking first; the five
RB cases all pass cvt(1) at `5%` tolerance which is generous.

This panic gates the entire smoke-test signature scan — every
"missing signature" report from `tools/test/ctest-boot-smoke.sh`
is downstream of this single early failure (kernel halts before
ring-3 smoke runs, before PCI scan completes, before the heartbeat
loop online).

## Runtime warnings/errors observed (release boot, OS healthy)

Counts collapsed across the heartbeat loop. Each row is a
distinct `subsystem : message` pair seen on serial.

### Expected / probe-emitted (no action)

| Source | Message | Why it's expected |
|--------|---------|-------------------|
| `core/klog` | `warn-level sanity line` | klog channel smoke probe |
| `core/klog` | `error-level sanity line` | klog channel smoke probe |
| `arch/smbios` | `no SMBIOS entry point — skipping` | QEMU q35 doesn't ship SMBIOS unless enabled |
| `arch/thermal` | `non-Intel vendor — Intel thermal MSRs would #GP, skipping` | Detection works; QEMU TCG is AuthenticAMD |
| `drivers/audio` | `no PCI audio controllers found (QEMU default q35 is silent)` | QEMU q35 has no HDA on default cmdline |
| `drivers/ps2mouse` | `port-2 self-test no response (no PS/2 mouse?)` | QEMU q35 default has no PS/2 mouse |
| `subsystems/graphics` | `graphics ICD skeleton present; Vulkan/D3D entry points return ErrorIncompatibleDriver` | Documented skeleton |
| `drivers/power` | `power backend is a stub — real battery/AC needs AML interpreter; thermal is real MSR data` | Documented stub |
| `net/stack` | `stack bound but no packet I/O yet (skeleton slice)` | Documented skeleton (despite e1000e MMIO bring-up living elsewhere) |
| `diag/soft-lockup` | `soft-lockup val=0xffffffff` (×2 in early boot) | Self-test exercises detector + reset |
| `syscall-gate` | `cap denied val=0x{4,5,7,18,...,aa}` (~20 distinct caps) | ring-3 smoke probes deliberately attempt out-of-cap calls and assert denial; intended adversarial coverage |

### Worth scrutinising (surfaced during normal release boot)

| Subsystem | Message | Why it deserves a follow-up look |
|-----------|---------|----------------------------------|
| `win32/heap` | `DoHeapAlloc: OOM at requested size val=0x10000` (64 KiB) | A 64 KiB allocation is small for a process heap. Either the per-process heap arena is undersized (current allocator yields ~2 MiB total free at boot per the heartbeat tally) or the heap call site is on a code path that should have grown the heap and didn't. |
| `win32/heap` | `DoHeapRealloc: returned 0 (OOM or invalid ptr) val=0x50000170` | Downstream of the OOM above — but the high `val` looks like an address, not a size; if it's a pointer that escaped from a freed handle the message is lying about whether it was OOM vs invalid. Worth distinguishing. |
| `win32/heap` | `process heap exhausted (HeapAlloc returned NULL)` | The PE smoke probe survives this; verify whether real-world PEs (windows-kill.exe path) can also tolerate, or whether this masks a leak. |
| `win32/tls` | `DoTlsFree: idx out of range val=0x1000` | A PE called `TlsFree(0x1000)`. Either a probe is feeding a deliberately-bad index (in which case the warning is correct and silent expected) or a real PE has a stale TLS handle. The serial doesn't say which PE issued it. |
| `pe-resolve` | 36 distinct `unknown import -> catch-all NO-OP` lines (from 11 DLLs) | Each is an unimplemented Win32 API. The list (e.g. `LoadLibraryW`, `K32EnumProcessModules`, `IsClipboardFormatAvailable`, `GdiplusStartup`, `EventRegister`, `_clearfp`, `midiOutGetNumDevs`, `sndPlaySoundA`) is a candidate workload for the porting-candidate inventory — but separate from the runtime-stability question. Expected for v0; not a stability bug. |
| `pe-resolve` | `import resolved to NO-OP stub fn="?cout@..."` and `data-miss zero pad fn="?cout@..."` | Same stub gets re-resolved twice — implicit suggestion that the resolver caches data-symbol misses and code-symbol stubs in different tables. Cosmetic, not a stability bug. |

### Debug-only additional warnings

The debug smoke run (before its CVT panic) also surfaced these,
which are absent from the release path:

| Subsystem | Message | Status |
|-----------|---------|--------|
| `selftest.fault-react` | `device-timeout val=0x1` / `0xffffffff`, `dma-error val=0x1` | **Expected** — fault-react self-test exercises the dispatcher with synthetic faults; "PASS" line follows |
| `lockdep` | `inversion detected newly-acquired="selftest-A" vs already-held class="selftest-B"`; `held-stack overflow; dropping deepest lock` | **Expected** — lockdep self-test feeds a deliberate inversion to assert detection works |
| `init` | `callback failed val=0x11 (17)` | Expected — init-callback selftest with a contrived failure (return code 17) to assert the init harness propagates the result |
| `diag/ubsan` | `unknown val=0xffffffff` | Expected — ubsan-handler self-test fires a synthetic UB report |
| `mm/zone` | `AllocateZoneFrame: Mmio zone has no backing pool` | **Worth checking** — the release boot doesn't hit this path. If it's only firing in debug because of an extra pre-allocation by a debug-only TU, fine; if it indicates the Mmio zone is genuinely unbacked at this point in boot, callers downstream of this allocator on real hardware would see allocation failures. |

## Boot smoke test status

`ctest -V` invocation `tools/test/ctest-boot-smoke.sh
build/x86_64-debug` exits **1** because of the CVT panic. The
cascade of "MISSING:" lines after the panic in the test output
is downstream of the kernel halting at 414 ms — none of the
expected signatures (e.g. `[hello-pe] Hello from a PE
executable!`) can ever fire because ring-3 smoke runs after the
CVT self-test.

Resolving the CVT panic should make the smoke test pass without
any further fixes (release boot proves all the downstream
signatures fire correctly when the kernel is allowed to reach
that scope).

## Follow-up worth picking from this list

Ranked from "highest correctness signal per hour of work":

1. **CVT pixel-clock case mismatch** (`kernel/drivers/gpu/cvt.cpp:286-299`). Identify the failing case (likely `1280x1024@60 STD`), recompute the expected value with cvt(1), or fix the formula. Single-file change. Unblocks the entire boot smoke test.
2. **`-Wunused-variable` in `cvt.cpp:201,205`** — likely the same bug as #1; fix together.
3. **`-Wmissing-field-initializers` in `theme.cpp` (5 sites)** — `font_kind` was added to a struct without back-filling initializers. Trivial.
4. **`-Wreturn-type` in `userland/apps/{syscall,thread}_stress/hello.c`** — non-void function falls off end. Two-line fix each.
5. **`-Wmemset-transposed-args` in `string.cpp:108`** — wrap the deliberate `memset(.,.,0)` in a small no-warning helper or use `(void) std::memset(buf, 0xFF, n)` with `n` made `volatile`.
6. **`-Wshadow` cleanup in `syscall.cpp` (17 sites)** — every site is `Process* proc = CurrentProcess()` shadowing the file-scope `const Process* proc` at line 436. Pick one of: (a) remove the file-scope binding (it's at line 436 inside an unrelated function — read the file before deciding), (b) rename inner locals to `cur_proc` / `child_proc`. Mechanical. Worth doing in one pass once the call.
7. **`win32/heap` OOM at 64 KiB** — investigate whether the per-process heap is actually too small or the test workload is leaking. Run windowed_hello / mini_browser with the heap probes on.
8. **`mm/zone : Mmio zone has no backing pool`** — debug-only; check whether a debug initcall is hitting an allocation path the release boot avoids, vs. a real coverage gap.

Items 1–5 are mechanical cleanups; items 6–8 deserve their own
investigation slices.

## See also

- `.claude/knowledge/cvt-cea861-v0.md` — original CVT slice that
  introduced `CvtSelfTest()`.
- `tools/test/ctest-boot-smoke.sh` — smoke driver + signature list.
- `.claude/knowledge/clang-format.md` — canonical format command.
- `.claude/knowledge/qemu-smoke-profile-matrix-v0.md` — multi-preset
  QEMU smoke harness.
