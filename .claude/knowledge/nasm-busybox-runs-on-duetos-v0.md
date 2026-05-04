# NASM 2.16.03 + busybox-w32 — bring-up pass on DuetOS, 2026-05-04

Two more "really complicated" Windows console PEs wired into the
smoke harness alongside 7-Zip:

| Property            | 7za.exe     | busybox64.exe   | nasm.exe         |
| ------------------- | ----------- | --------------- | ---------------- |
| Binary size         | 1.29 MiB    | 717 KiB         | 1.57 MiB         |
| Total imports       | 138         | 313             | 117              |
| CRT family          | msvcrt      | msvcrt (MinGW)  | UCRT (apisets)   |
| Subsystem           | Console     | Console         | Console          |
| Status on DuetOS    | full output | early task-kill | partial output   |

## Outcomes

- **NASM** loads + runs CRT init + reaches `main()` + prints
  `critical: nasm: out of memory!` to stderr (the no-args path's
  internal-pool error message). Then with the bumped 256 KiB heap
  it advances further into argv parsing and hits its own
  `argv[1][0] == '@'` check (NASM's response-file detector) which
  faults in NASM's own code — `cmpb [rcx], 0x40` with `rcx=0` —
  because NASM doesn't bound-check before walking past
  `argv[argc-1]`. Sentinel still reaches; no kernel panic.
- **busybox-w32** loads + runs CRT init + faults in MinGW's
  startup-time argv-walk (`mov rax, [rbx]` where `*rbx == NULL`).
  Same root cause as NASM: a CRT global was supposed to hold an
  argv-pointer that our setup didn't populate. MinGW's startup
  takes a different code path from MSVC/UCRT's `__getmainargs`
  entry, so the fix needs more cmdline-parse infrastructure
  than this slice ships. Sentinel still reaches; no kernel panic.

## Infrastructure landed (broadly useful for any Windows PE)

### 1. `__getmainargs` real thunk (`kOffGetMainArgs`, 36 bytes)

Replaces the `kOffReturnZero` stub that left the caller-supplied
`*p_argv` slot at NULL. New thunk reads from the proc-env page:

- `*p_argc = proc_env.argc`         (1)
- `*p_argv = proc_env.argv_ptr`     (= `proc_env + 0x20` array)
- `*p_env  = proc_env.env_block`    (empty, `proc_env + 0x400`)

Without this, classic MSVC CRT walked NULL argv and faulted at
`cr2=1` probing the second char of `argv[0]` for a Windows
drive-letter prefix.

Registered for `msvcrt.dll`, `ucrtbase.dll`,
`api-ms-win-crt-runtime-l1-1-0.dll` (3 link paths).

### 2. `_errno` real thunk (`kOffPErrno`, 6 bytes)

Returns `kProcEnvVa + kProcEnvDataMissOff` — the proc-env data
miss zero pad, which is page-aligned writable scratch. Callers do
`*_errno() = EINVAL` (write) and `if (*_errno() == EAGAIN)` (read);
both work against the shared scratch in single-thread v0.

Without this, NASM faulted at `cr2=0` in its first stdio call
(`call _errno; mov eax, [rax]` → `mov eax, [0]`).

Registered for `msvcrt.dll`, `ucrtbase.dll`,
`api-ms-win-crt-runtime-l1-1-0.dll`.

### 3. Per-name data-import override (`Win32ThunksLookupDataNamed`)

New helper in `subsystems/win32/thunks.cpp`. Extends the data
import path with named overrides that point well-known CRT
globals at their proc-env slots instead of the all-zeros catch-all
data-miss pad:

| Import name         | Resolves to                              |
| ------------------- | ---------------------------------------- |
| `__argv` / `_argv`  | `proc_env + 0x08`  (argv pointer slot)   |
| `__argc` / `_argc`  | `proc_env + 0x00`  (argc u32 slot)       |
| `_acmdln`           | `proc_env + 0x380` (narrow cmdline str)  |
| `_wcmdln`           | `proc_env + 0x300` (wide cmdline str)    |

Wired into `pe_loader.cpp`'s data-import path before the
catch-all. New log message `"data import -> proc-env named slot"`
distinguishes the case in the boot log.

### 4. UCRT apiset stdio table coverage

7-Zip imports `fputs` / `fputc` / `fwrite` from `msvcrt.dll`;
NASM imports the same from `api-ms-win-crt-stdio-l1-1-0.dll` (the
apiset DLL name MSVC's UCRT-link-mode emits). Existing thunks
were registered only under `msvcrt.dll`, so NASM's calls
NO-OP'd silently and the program exited rc=2 with no visible
output.

Added 24 new entries:

- `api-ms-win-crt-stdio-l1-1-0.dll` × {fputs, puts, fwrite, fputc,
  putchar, fflush, fgetc, feof, ferror, fclose, fread, getc}
- `ucrtbase.dll` × same surface (7 entries)
- `api-ms-win-crt-runtime-l1-1-0.dll` × {`__getmainargs`, `_errno`}

### 5. `kWin32HeapPages` 16 → 64 (256 KiB user heap)

NASM's "out of memory" error fired with the prior 64 KiB heap.
Bumped 4× to 64 pages. Tried 256 (1 MiB) first — broke 7-Zip
with a frame-allocator double-free panic in the AS destroy path,
suggesting the trusted budget interaction needs more thought
before that bigger jump. 64 pages keeps every existing profile
clean (bringup / pe-winapi / pe-sevenzip / pe-busybox / pe-nasm /
linux all sentinel) while letting NASM advance past its first
malloc call.

### 6. Smoke profile + ramfs wiring for both PEs

- `SmokeProfile::PeBusyBox` + `SmokeTarget::PeBusyBox`
- `SmokeProfile::PeNasm` + `SmokeTarget::PeNasm`
- `pe-busybox` / `pe-nasm` cmdline parser cases
- 30-second sleep tick budgets each
- `!emulator` gate under `SmokeProfile::None`
- `/bin/busybox64.exe` + `/bin/nasm.exe` ramfs entries
- `kBinBusyBoxBytes` + `kBinNasmBytes` embeds

## Verification

| Profile     | exit | Sentinel | bare FAIL | session       | Notes                         |
| ----------- | ---- | -------- | --------- | ------------- | ----------------------------- |
| bringup     | 33   | reached  | 0         | OK            |                               |
| pe-winapi   | 33   | reached  | 0         | OK            |                               |
| pe-sevenzip | 33   | reached  | 0         | OK            | 66 lines of 7-Zip help        |
| pe-busybox  | 33   | reached  | 0         | OK            | task-killed in MinGW startup  |
| pe-nasm     | 33   | reached  | 0         | OK            | task-killed in argv walk      |
| linux       | 33   | reached  | 0         | OK            | 598 ELF stdout lines          |

Zero kernel panics across the matrix.

## Follow-up gaps (deferred)

- `__stdio_common_vfprintf` / `__stdio_common_vfwprintf` left
  NO-OP. NASM's `fprintf(stderr, "format", args...)` paths can't
  print formatted strings yet. A real implementation needs a
  full printf engine (`%s`, `%d`, `%x`, padding, precision); the
  cheap escape would be a passthrough-format thunk that strips
  args and prints just the format string.
- busybox-w32's MinGW CRT calls argv-init helpers we don't
  recognise yet — needs a sweep of MinGW's `crt0.S` / `mainCRTStartup`
  to identify which globals it expects pre-populated.
- NASM's argv-walk faults when it walks past `argv[argc-1]`
  expecting a non-NULL sentinel. Either pad argv with a dummy
  entry or emit a synthetic command line that gives NASM at
  least one real argument.
- The 1 MiB heap bump that broke 7-Zip needs investigation —
  AS destroy double-free with `regions=0x1d3` after only +1
  region from heap init, suggesting a frame leak path elsewhere
  in the partially-initialised state. Stayed at 64 pages for now.
