# Live boot + executable smoke pass — 2026-05-04

Triggered by user request: "boot up the OS and live test Windows and
Linux executables, fix whatever issues occur." Installed the runtime
tooling per CLAUDE.md → "Live-test runtime tooling — install on demand"
(`qemu-system-x86 grub-common grub-pc-bin grub-efi-amd64-bin xorriso
mtools ovmf`), built `x86_64-debug`, and ran every smoke profile.

## Findings (and fixes)

### 1. `__WSAFDIsSet` missing from `ws2_32.dll`

`select_smoke` failed `FD_ZERO + FD_SET` because mingw-w64's
`<winsock2.h>` lowers `FD_ISSET(s, set)` to a call into
`__WSAFDIsSet(s, set)`, and `ws2_32.dll` never exported that
function. The PE loader resolved the import to the catch-all NO-OP
stub (`pe-resolve : import resolved to NO-OP stub fn="__WSAFDIsSet"`),
so the smoke saw `0` for "fd 42 is in the set we just put it in" → bare
`FAIL` line on the serial log.

Fix: implemented `__WSAFDIsSet` in
`userland/libs/ws2_32/ws2_32.c` and added it to the `/export:` list in
`kernel/CMakeLists.txt:534`. The implementation walks the caller's
`fd_set` struct using the mingw-w64 layout
(`{ u_int fd_count; SOCKET fd_array[FD_SETSIZE]; }` where `SOCKET` is
`UINT_PTR` so `fd_array` starts at offset 8 with 8-byte stride).

After: `[select_smoke] FD_ZERO + FD_SET = PASS` and the stub_miss
probe stops firing on `__WSAFDIsSet`.

### 2. `WindowMoveTo` clamps everything to (0, 0) before the framebuffer is up

`SessionRestoreSelfTest` (`kernel/core/session_restore.cpp:357`) round-
trips a synthetic `theme=amber\nwin.0.x=42\nwin.0.y=84\n` payload
through `ApplyPayload` and asserts `WindowGetBounds(calc) == (42, 84)`.
The bounds came back `(0, 0)`.

Root cause: `WindowMoveTo` in `kernel/drivers/video/widget.cpp:747`
unconditionally clamps `(x, y)` against
`info.width - chrome.w` / `info.height - chrome.h`. When the
self-test runs early in boot (before `FramebufferInit`),
`info.width` and `info.height` are zero, so `max_x = max_y = 0` and
any nonzero target collapses to the origin.

Fix: gate the clamp on `FramebufferAvailable()`. Pre-init moves now
trust the caller; once the framebuffer is up, clamping resumes.

After: `[session] self-test OK (theme + window position round-trip)`.

## Refactor — `DumpOnAbnormalExit` → `DumpExitDiagnostics`

The function fires on **every** Win32 PE exit (success and abnormal
alike) — it's the per-process post-mortem dump that lets a clean run
and a faulting run leave the same shape on the serial log so divergence
diffs are cheap. The old name implied "only on crash," which actively
misled new readers (the boot log is full of `[w32-custom]
abnormal-exit dump pid=… policy=…` lines for processes that exited
cleanly with `rc=0`).

Renamed across:

- `kernel/subsystems/win32/custom.h` — declaration + comment
- `kernel/subsystems/win32/custom.cpp` — definition + serial-log
  prefix (`abnormal-exit dump` → `exit-diagnostics`) + internal call
  from `kOpDumpFlight`/etc.
- `kernel/subsystems/win32/custom_selftest.cpp` — comments + the
  selftest invocation
- `kernel/proc/process.cpp` — the per-exit call site + the trace stamp
  (`post-DumpOnAbnormalExit` → `post-exit-diagnostics`)

Historical `docs/example-boot-log-debug.txt` left as-is (it's a
captured artifact; future regenerations will pick up the new label).

## Diagnostic-logging discipline (added to CLAUDE.md)

User asked for the "keep diagnostics, gate them, hook the GDB/BP
system" pattern to be documented so future sessions follow it.
`CLAUDE.md` now has a "Diagnostic Logging — Keep It, Gate It, Probe It"
section (between "Wiring Things In" and "Persistence Context Database")
that codifies the rule:

1. Don't strip diagnostic lines added during a fix — they're exactly
   what the next session will want.
2. Use `KLOG_WARN` for the failure summary, `KLOG_DEBUG_V` /
   `KLOG_DEBUG_S` for verbose detail. Avoid raw `arch::SerialWrite`
   for new diagnostics.
3. Fire `KBP_PROBE_V(kBootSelftestFail, fail_value)` on the failure
   leg so an attached GDB stub halts at the regression.

Concrete example landed: the new session_restore sub-check failures
emit `KLOG_WARN` summaries, `KLOG_DEBUG_V` observed values, and fire
`kBootSelftestFail` (new probe ID added to `ProbeId` +
`kProbeTable`) with a 2-bit value encoding which sub-check tripped.

## Verification

All four smoke profiles complete + sentinel + zero bare `FAIL` lines
+ session OK on this branch:

| Profile     | exit | Sentinel | bare FAIL | session       |
| ----------- | ---- | -------- | --------- | ------------- |
| bringup     | 33   | reached  | 0         | OK            |
| pe-hello    | 33   | reached  | 0         | OK            |
| pe-winapi   | 33   | reached  | 0         | OK            |
| pe-winkill  | 33   | reached  | 0         | OK            |
| linux       | 33   | reached  | 0         | OK (599 ELF lines from synxtest+synfs+synet+synfull) |

Hello-PE printed `[hello-pe] Hello from a PE executable!`. Linux
ELFs ran end-to-end producing real syscall output (`[exe] mmap anon
ok`, `[fs] write(SYNFS.TMP,11) rc=11`, `[net] start`, `[full] N=…`
across all 463 syscall slots).
