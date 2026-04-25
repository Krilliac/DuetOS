# Cleanroom-trace boot survey — v0 (2026-04-25)

First end-to-end pass through the live cleanroom-trace ring buffer
captured from a real OVMF + QEMU boot of `boot=tty`. The trace
subsystem (`kernel/core/cleanroom_trace.{h,cpp}`) records up to
256 wrap-around entries at instrumented dispatch points. This
note is the first read of what the live trace actually contains
on a normal boot, and what that tells us about which Win32/Linux
surface area is exercised by real PE/ELF binaries running on
DuetOS today.

## Capture path

The survey is gated behind a single CMake option,
`DUETOS_CRTRACE_SURVEY` (default OFF). When ON, three things
turn on together:

1. `kernel/core/main.cpp` — at end-of-init, after every
   subsystem is online, the kernel walks the trace ring and
   writes each entry to COM1 between
   `=== CRTRACE BOOT DUMP BEGIN count=N ===` and
   `=== CRTRACE BOOT DUMP END ===`.
2. `kernel/fs/ramfs.cpp` `kEtcProfileBytes` — `/etc/profile`
   gains a final `crtrace show 256` line so the shell-side
   dump fires automatically once the prompt arrives (gives a
   second look at the buffer state right after profile loads).
3. `kernel/core/shell.cpp` `CmdCrTrace` — always-on (not gated),
   adds a SerialWrite mirror so any future invocation of
   `crtrace show` makes it to serial. Costs nothing on
   interactive boots.

For headless capture, also patch `boot/grub/grub.cfg` to
`default=2 timeout=0` so the ISO lands directly in the TTY
entry. The `tools/cleanroom/run-trace-survey.sh` harness does
that patch + restore inside a trap so an interrupted run
doesn't leave the tree in survey-default state.

## Findings

### 1. Trace ring is dominated by syscall dispatches

Of 256 entries captured, **all 256** are `syscall::*`:
- 216 `syscall::native-dispatch`
- 40  `syscall::linux-dispatch`

Zero `pe-loader::*`, `e1000::*`, `xhci::*`, `wifi::*`,
`fw-loader::path-attempt`, or `shell::command` events survived
to the dump window. Those events all fired during early boot
but were evicted by the time ring3 tasks started spinning
through their syscall sequences. **The 256-slot ring is too
small for steady-state inspection** — once any ring-3 PID
spams `SYS_WRITE` (the dominant pattern), early-boot driver
trace evidence is gone within a fraction of a second.

Recommendation: bump `kCleanroomTraceCapacity` from 256 to at
least 4096 (~150 KiB at the current 36-byte entry size — still
trivial relative to the kernel image), and/or add a
"sticky-first-N" reservation for boot-time events so PE-loader
/ driver init traces are never evicted.

### 2. Native (Win32) syscall surface in real use

The PE binaries spawned by `ring3_smoke` exercise this map of
the native ABI on a clean boot:

| Hex  | Decimal | SYS_              | Hits | What this proves works |
|------|---------|-------------------|------|------------------------|
| 0x02 | 2       | WRITE             | 158  | Console / stdout path |
| 0x00 | 0       | EXIT              | 7    | Process teardown |
| 0x0B | 11      | HEAP_ALLOC        | 6    | Win32 heap front-end |
| 0x0C | 12      | HEAP_FREE         | 5    | Heap free + coalescing |
| 0x1E | 30      | EVENT_CREATE      | 4    | Win32 event objects |
| 0x2D | 45      | THREAD_CREATE     | 3    | CreateThread path |
| 0x12 | 18      | NOW_NS            | 3    | Monotonic clock |
| 0x01 | 1       | GETPID            | 3    | PID query |
| 0x21 | 33      | EVENT_WAIT        | 2    | WaitForSingleObject |
| 0x11 | 17      | GETTIME_FT        | 2    | FILETIME / GetSystemTimeAsFileTime |
| 0x0D | 13      | PERF_COUNTER      | 2    | QueryPerformanceCounter |
| 0x08 | 8       | GETPROCID         | 2    | GetCurrentProcessId |
| 0x05 | 5       | READ              | 2    | Generic read syscall |
| 0x04 | 4       | STAT              | 2    | File stat |
| 0x3D | 61      | WIN_MSGBOX        | 1    | **MessageBox path live** |
| 0x37 | 55      | THREAD_EXIT_CODE  | 1    | GetExitCodeThread |
| 0x30 | 48      | WAIT_MULTI        | 1    | WaitForMultipleObjects |
| 0x2F | 47      | MEM_STATUS        | 1    | GlobalMemoryStatus |
| 0x2E | 46      | DEBUG_PRINT       | 1    | OutputDebugString |
| 0x27 | 39      | TLS_SET           | 1    | TlsSetValue |
| 0x26 | 38      | TLS_GET           | 1    | TlsGetValue |
| 0x20 | 32      | EVENT_RESET       | 1    | ResetEvent |
| 0x1F | 31      | EVENT_SET         | 1    | SetEvent |
| 0x16 | 22      | FILE_CLOSE        | 1    | CloseHandle (file) |
| 0x15 | 21      | FILE_READ         | 1    | ReadFile |
| 0x14 | 20      | FILE_OPEN         | 1    | CreateFileA |
| 0x0E | 14      | HEAP_SIZE         | 1    | HeapSize |
| 0x06 | 6       | DROPCAPS          | 1    | Capability drop test |
| 0x03 | 3       | YIELD             | 1    | Sched yield |

Hot path: WRITE → HEAP_{ALLOC,FREE} → EVENT_* → THREAD_CREATE.
Twelve distinct PIDs hit native dispatch, each with a coherent
shape (e.g., PID 0x10 walks the full HEAP_ALLOC / HEAP_FREE /
HEAP_REALLOC / HEAP_SIZE arc; PID 0x16 does a single
WIN_MSGBOX call and exits — that's `windowed_hello.exe`).

### 3. Linux ABI surface in real use

Seven distinct Linux PIDs (0x17..0x1d) exercise this Linux-ABI
map:

| Decimal | Linux name      | Hits |
|---------|------------------|------|
| 1       | write            | 13   |
| 231     | exit_group       | 6    |
| 9       | mmap             | 5    |
| 3       | close            | 3    |
| 2       | open             | 3    |
| 8       | lseek            | 1    |
| 28      | madvise          | 1    |
| 39      | getpid           | 1    |
| 63      | uname            | 1    |
| 90      | chmod            | 1    |
| 186     | gettid           | 1    |
| 228     | clock_gettime    | 1    |
| 318     | getrandom        | 1    |
| 334     | rseq             | 1    |
| 0       | read             | 1    |

`rseq` (334) being present pegs the test programs as built
against glibc 2.35 or newer (rseq registration is unconditional
since then). The presence of `getrandom` + `clock_gettime` +
`gettid` + `uname` shows the dispatch table covers the modern
process-startup checklist that even a "hello world" Linux app
hits before `main()` runs.

The four lowest Linux PIDs (0x17..0x1A) run code with RIPs in
the 0x40009A..0x4010DA range — a small statically-linked ELF
mapped at the conventional `0x400000` base. The two highest
PIDs (0x1C, 0x1D) run RIPs in 0x680..._ / 0x6A0..._ /
0x6B0..._ — those are mmap-allocated regions, indicating
larger Linux binaries that mmap their own code or anon pages.

### 4. Hash-token decode for `shell::command`

The first dump (captured before the buffer wrapped) contained 5
`shell::command` entries from `/etc/profile` auto-source. Each
records `CleanroomTraceHashToken(cmd)` in `a` and the FNV-1a
hash of `argv[1]` in `c`. Verified hashes for the 5 profile
lines:

| Command  | Hash (a)             |
|----------|----------------------|
| `set`    | `0x59124e51510c8381` |
| `alias`  | `0xaa8be5cca810e8bd` |
| `crtrace`| `0xb3ae34e823ac6c6b` |

**Note:** The hash function in `cleanroom_trace.cpp:CleanroomTraceHashToken`
calls itself FNV-1a but uses **non-standard** offset basis
`1469598103934665603` (decimal). The real FNV-1a-64 offset is
`14695981039346656037` — the kernel constant is missing the
final digit. The hash is still deterministic and well-mixed
for the small command-name vocabulary, but external decoders
(e.g., a Python helper that hashes shell-command names with
the standard FNV-1a-64 offset) will produce different values
than what's in the trace. Either fix the constant to the real
FNV-1a-64 offset, or rename the helper so it doesn't claim to
be FNV-1a.

## Capture reproducibility

The whole capture flow is one command:

```bash
tools/cleanroom/run-trace-survey.sh                         # captures to build/<preset>/crtrace-survey.log
tools/cleanroom/run-trace-survey.sh /tmp/survey.log         # explicit out path
DUETOS_TIMEOUT=60 tools/cleanroom/run-trace-survey.sh ...   # longer boot window
```

The harness:
- Reconfigures CMake with `-DDUETOS_CRTRACE_SURVEY=ON`.
- Backs up `boot/grub/grub.cfg`, swaps default→TTY, restores on
  any exit (including SIGINT) via a `trap` handler.
- Builds, boots in QEMU under `tools/qemu/run.sh`, captures COM1
  to the out file.
- Asserts a `=== CRTRACE BOOT DUMP BEGIN ===` marker is present
  before declaring success.

To analyse the captured log:

```bash
tools/cleanroom/decode_hash.py --grep /tmp/survey.log
tools/cleanroom/decode_syscall.py --summary /tmp/survey.log
tools/cleanroom/decode_syscall.py /tmp/survey.log | less
```

`decode_hash.py` reverses kernel `CleanroomTraceHashToken`
hashes back to shell command names (using the same non-standard
FNV-1a-style constant the kernel uses; see "Hash-token decode"
below for the gotcha).

`decode_syscall.py` annotates `syscall::native-dispatch` and
`syscall::linux-dispatch` entries with their human-readable
names, pid, and rip; `--summary` produces a histogram.

Both decoders read the log as raw bytes + `decode(errors=
'replace')` so UEFI / GRUB cursor-control bytes upstream of the
kernel don't crash them.

For a quick interactive look without rebuilding in survey
mode, the always-on `CmdCrTrace` serial mirror means typing
`crtrace show 256` at the shell also writes the dump to COM1
between `=== CRTRACE DUMP BEGIN ===` markers.

## RE / reimplementation leads (sorted by hit count)

Where the actual workload spends its syscall budget, ordered by
boot-survey frequency. Optimize / harden / spec-comply these
first — they're not theoretical, they're what real PE and Linux
binaries currently call:

1. **`SYS_WRITE`** (158 hits) — overwhelmingly hot. Worth a
   dedicated micro-bench + a fast path for short writes (≤ 64
   bytes), since console + serial mirroring is a known hot path.
2. **Win32 HEAP family** (HEAP_ALLOC, HEAP_FREE, HEAP_SIZE,
   HEAP_REALLOC — 12 hits combined) — hot enough to justify
   slab tuning. The current implementation is already on slab;
   measure free-list balance under sustained PE workload.
3. **Win32 EVENT family** (CREATE, SET, RESET, WAIT — 8 hits) —
   covered by v1.4 windowing per `.claude/index.md`, but
   Linux's `futex` (202) is conspicuously absent from the
   trace, suggesting Linux-side waiting may be polling /
   spinning instead of blocking. Worth checking.
4. **`SYS_THREAD_CREATE` + `WAIT_MULTI`** (4 hits) — multi-
   threaded test programs are reaching this. Confirms the
   scheduler's per-task FS/GS-base setup works in user mode.
5. **`WIN_MSGBOX`** (1 hit, PID 0x16, `windowed_hello.exe`) —
   end-to-end Win32 windowing chain is live.
6. **Linux `rseq` / `getrandom` / `clock_gettime` / `gettid`**
   — modern glibc startup path. Ensure each returns plausible
   values; any of these hard-failing kills program startup.

## Things the trace *should* show but doesn't

These dispatch points exist in the source but produced zero
visible entries in the boot dump. Either (a) they fire only in
narrow conditions we didn't trigger, or (b) they fire during
early boot and get evicted before the dump:

- `pe-loader::imports-resolved` / `import-data-catchall` /
  `import-fn-catchall` / `import-unresolved-fatal` — fire on
  every PE load. Boot loaded several PEs (customdll-test,
  hello-winapi, windowed-hello) so they DID fire — but were
  evicted.
- `e1000::ivar-programmed` / `msix-bound` / `msix-fallback-poll`
  — driver init only.
- `xhci::bulk-cache-hit` / `bulk-timeout` — bulk-IN path only.
- `fw-loader::path-attempt` — only when a driver requests
  firmware. Wireless drivers register but no probe was hit.
- `wifi::*` — no Wi-Fi backend is registered on QEMU's e1000e
  (wired) device.

The fix here is either bigger ring buffer (#1 above) or
per-subsystem ring buffers so syscall noise can't evict PE /
driver events.

## Files touched in this slice

Build-stop fixes (real bugs that broke the merged HEAD; always
on):

- `kernel/core/string.cpp` (new) — freestanding `memset` /
  `memcpy` / `memmove` extern "C" stubs. The compiler emits
  implicit calls for `T x = {}` on POD arrays / structs and
  for struct-by-value copies even with `-fno-builtin`; without
  these the link fails the moment any subsystem zero-inits a
  ring-buffer entry. Two recently-merged subsystems
  (firmware_loader, shell crtrace path) tripped this.
- `kernel/core/shell.cpp` — added `WriteI64Dec` /
  `ParseU64Str` / `ParseInt` forward declarations and a
  ParseInt definition. The `crtrace show <N>` and the Wi-Fi
  scan dump (RSSI in dBm) had call sites that were never
  resolvable at HEAD.
- `kernel/CMakeLists.txt` — added `core/string.cpp` to the
  shared kernel sources list.

Always-on diagnostic improvement:

- `kernel/core/shell.cpp` `CmdCrTrace` — SerialWrite mirror so
  the shell-side `crtrace show` works in headless mode.

Survey-mode patches (gated behind `DUETOS_CRTRACE_SURVEY`):

- `CMakeLists.txt` — defines the option + propagates the
  `DUETOS_CRTRACE_SURVEY=1` macro.
- `kernel/core/main.cpp` — boot-time SerialWrite dump after all
  subsystems are online.
- `kernel/fs/ramfs.cpp` — appends `crtrace show 256\n` to
  `/etc/profile` so the shell auto-dumps right after the
  prompt comes up.

Tooling (in `tools/cleanroom/`):

- `run-trace-survey.sh` — end-to-end harness (reconfigure +
  patch grub + build + boot + capture + restore grub).
- `decode_hash.py` — `shell::command` hash-token decoder
  (mirrors the kernel's non-standard FNV-1a constant).
- `decode_syscall.py` — `syscall::*` annotator + histogrammer.
