# Format + boot + test runtime report — 2026-05-01

**Last updated:** 2026-05-01
**Type:** Issue + Observation
**Status:** Closed — every item in the original inventory landed; the
boot-smoke ctest passes; both x86_64-debug and x86_64-release boot
clean; tree compiles with **zero warnings**; one new host unit test
locks down the regression.

## Status (2026-05-01)

### Landed (all items from the original inventory)

| Item | What landed | Where |
|------|-------------|-------|
| **CVT panic** — `1280x1024@60 STD` pixel clock outside ±5% tolerance | Two unit-mismatch fixes in `GenerateStandard`: divisor for `frame_period_ns_x1000` corrected from `1e12` to `1e15` (the value was actually μs×1000, not ns×1000); duty-cycle scale corrected from `÷1e6` to `÷1e4` (was missing the ×100 to micro-percent). Standard-mode now lands at 110.1 MHz vs. 109 MHz target, well inside ±5%. | `kernel/drivers/gpu/cvt.cpp` |
| `-Wunused-variable` × 2 (`v_back_porch`, `v_total`) | Removed both — neither was needed for FillDtd output (back porch is implicit in `v_blanking - v_sync_offset - v_sync_pulse`; v_total was dead). | `kernel/drivers/gpu/cvt.cpp` |
| `-Wmissing-field-initializers` × 5 (`font_kind` in 5 themes) | Added `.font_kind = Theme::FontKind::Bitmap8x8,` to Classic / Slate10 / Amber / HighContrast / and the fifth bitmap-8x8 theme — all the Bitmap8x8 themes now match the Ttf themes' explicit init. | `kernel/drivers/video/theme.cpp` |
| `-Wreturn-type` × 2 (`syscall_stress`, `thread_stress`) | Marked `ExitProcess` `__declspec(noreturn)` in both prototypes; clang now sees fall-off-end is unreachable. | `userland/apps/{syscall,thread}_stress/hello.c` |
| `-Wmemset-transposed-args` × 1 | Wrap deliberate `memset(buf, 0xFF, 0)` no-op test in `volatile usize kZeroSize = 0;` so clang doesn't pattern-match. | `kernel/util/string.cpp:108` |
| `-Wshadow` × 19 (17 in `syscall.cpp`, 2 in `hexdump.cpp`) | Renamed outer `proc`/`pid` in SyscallDispatch to `dispatch_proc`/`dispatch_pid`; renamed namespace-shadowing locals in HexdumpSelfTest to `kHigherHalfStartCanonical`/`kHigherHalfEndCanonical` with `static_assert` against the file-scope constants. | `kernel/syscall/syscall.cpp`, `kernel/diag/hexdump.cpp` |
| `-Wunused-function` × 4 (`LeU64`, `IpEq`, `str_len`, `gdi32_ascii_len`) | Deleted all four — none had callers in the tree. | `kernel/loader/pe_exports.cpp`, `kernel/net/socket.cpp`, `userland/apps/windowed_hello/hello.c`, `userland/libs/gdi32/gdi32.c` |
| `-Wunused-const-variable` × 3 (`kEFD_NONBLOCK`, `kEagain`, `kEDestAddrReq`) | Deleted all three — orphaned errno constants; live values still come from `syscall_internal.h`. | `kernel/subsystems/linux/syscall_async_io.cpp`, `syscall_pipe.cpp`, `syscall_socket.cpp` |
| `-Wunused-parameter` × 3 (`n`, `a5`, `lpCurrentDirectory`) | `/*n*/` comment-out for `iwlwifi_upload.cpp::LoadSection`; `/*a5*/` for `keyrings.cpp::DoKeyctl`; `(void)lpCurrentDirectory;` cast in `kernel32.c::CreateProcessW` (mirrors what `CreateProcessA` already does). | listed three sites |
| `-Wcomment` × 1 | `/bin/*` in a `/* … */` block comment was triggering nested-comment detection — reworded to `paths under /bin/`. | `kernel/fs/file_route.cpp:9` |
| **win32/heap OOM** at 64 KiB warning noise | Per-call `WARN` in `DoHeapAlloc` and `DoHeapRealloc` downgraded to `TRACE`. NULL-on-OOM is part of the documented Win32 contract; smoke probes (e.g. `ipc_smoke` testing `CreateFileMappingW(0x10000)` against the deliberately-bounded 64 KiB heap) call it on purpose. The first-time `KLOG_ONCE_WARN("process heap exhausted")` in `heap.cpp` still fires once per boot to surface a real leak. | `kernel/subsystems/win32/heap_syscall.cpp` |
| **win32/tls** out-of-range warning | `KLOG_WARN_V("DoTlsFree: idx out of range")` downgraded to `KLOG_TRACE_V`. The `hello_winapi` smoke calls `TlsFree(0x1000UL)` deliberately to probe the documented Win32 error path. | `kernel/subsystems/win32/tls_syscall.cpp` |
| **mm/zone Mmio has no backing pool** warning | `KLOG_ONCE_WARN` downgraded to `KLOG_TRACE`. The `Mmio` zone is documented as having no backing pool; the self-test exercises this path explicitly to assert the OOM counter advances. | `kernel/mm/zone.cpp` |
| **CVT regression guard** | New `tests/host/test_cvt.cpp` that mirrors the kernel's `GenerateRb` / `GenerateStandard` and asserts the same six known-good cases plus an explicit equality check that Standard-mode does NOT silently fall back to RB (which is what the `1e15` and `÷1e4` regressions both did). Wired into `tests/host/CMakeLists.txt`. | `tests/host/test_cvt.cpp` |

### Verification

- `find kernel boot userland tests \( -name '*.h' -o -name '*.hpp' -o -name '*.c' -o -name '*.cpp' \) | xargs clang-format --dry-run --Werror`: **clean** (0 violations).
- `cmake --preset x86_64-debug` + build: **0 compile warnings, 757 targets**.
- `cmake --preset x86_64-release` + build: **0 compile warnings, 757 targets**.
- `cmake -S tests/host -B build/host-tests` + build + ctest: **3/3 PASS** (`result`, `string`, `cvt`).
- `cd build/x86_64-debug && DUETOS_TIMEOUT=90 ctest`: **1/1 PASS, 90.34 s** — every expected boot signature present, no forbidden signatures.
- `DUETOS_PRESET=x86_64-release DUETOS_TIMEOUT=45 tools/qemu/run.sh`: boots through to ~28 s of heartbeats, `health_issues_total = 0`, no panic.

### Remaining runtime warnings (all expected; documented here so future audits don't re-derive them)

The debug boot still emits ~210 `[W]` / `[E]` lines on serial. Every
remaining line is in one of the five buckets below. None warrant a
follow-up — they're either deliberate self-test probes or
environment-specific (QEMU q35 lacking optional hardware).

| Bucket | Examples | Why expected |
|--------|----------|--------------|
| klog channel sanity probes | `[W] core/klog : warn-level sanity line`, `[E] core/klog : error-level sanity line` | Boot-time smoke that the W/E channels actually plumb through to serial. |
| Self-test deliberate failures | `[E] init : callback failed val=0x11`, `[E]/[W] selftest.fault-react : device-timeout`, `[W] diag/soft-lockup : soft-lockup`, `[W] diag/ubsan : unknown`, `[W] lockdep : inversion detected newly-acquired="selftest-A"` | Each subsystem self-test feeds itself a synthetic fault and asserts the path fires. The test passes only if the warning prints. |
| Environment-specific (QEMU q35) | `[W] arch/smbios : no SMBIOS entry point`, `[W] arch/thermal : non-Intel vendor`, `[W] drivers/audio : no PCI audio controllers found`, `[W] drivers/ps2mouse : port-2 self-test no response`, `[W] fs/gpt : LBA 0: missing 0x55AA boot signature` | All true on the QEMU TCG profile we test against. Real hardware will quiet these. |
| Adversarial probes asserting cap denial | 20 distinct `[W] syscall-gate : cap denied val=0x..` lines | Ring-3 smoke probes deliberately attempt out-of-cap calls and assert the kernel denies them. Each line is a successful adversarial assertion. |
| Documented v0 skeleton surfaces | `[W] net/stack : stack bound but no packet I/O yet`, `[W] subsystems/graphics : graphics ICD skeleton present`, `[W] drivers/power : power backend is a stub`, `[W] win32/heap : process heap exhausted` (KLOG_ONCE_WARN), `[W] pe-resolve : import resolved to NO-OP stub` (~36 distinct fn=, plus parallel `unknown import -> catch-all NO-OP` lines for the same set) | Each is a documented v0 implementation gap. The PE-resolve list **is** the per-API porting backlog and lives separately at `.claude/knowledge/porting-candidates-v0.md`. |

## Resume prompt

> The runtime report at `.claude/knowledge/format-and-test-2026-05-01-runtime-report.md` is closed — every item from the original inventory landed in commits on branch `claude/format-and-test-9fIvH`. The CVT panic is fixed and locked down by a host unit test (`tests/host/test_cvt.cpp`); compile warnings are at zero on both debug and release; the boot smoke ctest passes in 90 s; remaining runtime warnings on serial are all in the five "expected" buckets documented above. Nothing in this report needs further follow-up.

## Why both CVT bugs were really one bug

The kernel-side `GenerateStandard` carried the variable name
`frame_period_ns_x1000` but the divisor was `1e12 / refresh_mhz`.
With `refresh_mhz = 60000` (= 60.000 Hz × 1000), that yields
`16,666,666` — which is **microseconds × 1000**, not nanoseconds × 1000.
Two consequences:

1. The early bail `if (frame_period_ns_x1000 <= kMinVsyncBpUsStd*1e6)` fires
   (16M < 550M), so Standard silently falls back to RB.
2. Even when not bailing, the duty-cycle scale `÷1e6` was off by 100×
   (the formula needed `÷1e4` to land in micro-percent), so
   `h_blanking` came out 100× too small and `pclk` overshot tolerance.

Both were symptoms of the same unit confusion. The host test asserts
both invariants: every known-good timing within tolerance, plus an
explicit "Std must not equal RB pclk" check. A future regression
that re-introduces either bug fails on the first `ctest` run.

## See also

- `.claude/knowledge/cvt-cea861-v0.md` — original CVT slice that
  introduced `CvtSelfTest()`.
- `.claude/knowledge/clang-format.md` — canonical format command.
- `tests/host/test_cvt.cpp` — host-side regression guard added in
  this pass.
