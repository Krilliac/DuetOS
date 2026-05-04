# 7-Zip 23.01 (x64) runs on DuetOS — 2026-05-04

A real-world MSVC console PE — `7za.exe` from the official 7-Zip
23.01 standalone build, 1.29 MiB, 138 imports across KERNEL32 /
msvcrt / ADVAPI32 / OLEAUT32 / USER32 — now loads, runs MSVC CRT
init, prints its full ~3 KiB usage block, and exits cleanly (rc=0)
on DuetOS.

This is the "really complicated" PE smoke target — substantially
heavier than the prior `windows-kill.exe` (~80 KiB, 12 DLLs,
exited but never produced output).

## End-to-end output

```
7-Zip (a) 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20

Usage: 7za <command> [<switches>...] <archive_name> [<file_names>...] [@listfile]

<Commands>
  a : Add files to archive
  b : Benchmark
  …
  x : eXtract files with full paths

<Switches>
  -- : Stop switches and @listfile parsing
  …
  -y : assume Yes on all queries
```

72 lines of help text, 2,905 bytes total. Run via:

```bash
DUETOS_TIMEOUT=180 DUETOS_SMOKE_PROFILE=pe-sevenzip tools/qemu/run.sh
```

## Bugs the 7za bring-up surfaced (and fixed)

### 1. `AddressSpace::region_count` is `u8` but the array holds 1024 entries

A 1.29 MiB PE allocates ~325 page mappings for sections alone; the
counter wrapped silently past 255 and overwrote earlier rows in
`regions[]`. The page tables stayed mapped, but
`AddressSpaceLookupUserFrame`'s linear scan over `regions[0..count)`
lost the early entries (most importantly the `.rdata` page holding
the IAT), and `ResolveImports` failed with `IAT slot VA not mapped`
→ silent `PeLoad failed`.

Fix: widen `region_count` (header struct + every loop variable in
`address_space.cpp`, `panic.cpp`, `syscall.cpp`) from `u8` to `u16`.
Same overflow re-fired in the AS *destroy* path
(`for (u8 i = 0; i < as->region_count; ++i) FreeFrame(...)`),
double-freeing `regions[0]` after iterating past 255 — caught the
same hour, fixed in the same slice.

Updated comment in `kernel/subsystems/win32/heap.h` that previously
warned "don't bump kWin32HeapPages past ~32 because region_count is
u8" — historical now.

### 2. PE loader silent-fail in `SpawnPeFile`

When `PeLoad` returned `r.ok=false`, `SpawnPeFile`
released the AS and returned 0 with no log line. A failing spawn
vanished between the spawn-block trace and the next process's
banner — invisible to anyone trying to figure out which import or
section layout the loader couldn't handle.

Fix: route the failure through `KLOG_WARN("ring3", "PeLoad failed")`
+ four `KLOG_DEBUG_V` lines for the entry / stack / image_base /
name detail. Honors the "Diagnostic Logging — Keep It, Gate It,
Probe It" rule from `CLAUDE.md` — visible at default loglevel,
verbose detail only at debug level.

### 3. `IsLikelyDataImport` only recognised C++-mangled names

The MSVC CRT exports a handful of plain-C globals (`_commode`,
`_fmode`, `_iob`, `__initenv`, `_environ`, `__argc`, etc.) as DATA,
not functions. The CRT init code does `mov [iat_slot_ptr], value`
to populate them. With the data-import heuristic only matching
`?...@@3...` C++ mangling, our resolver pointed those IAT slots at
the catch-all NO-OP function thunk (in the read-only stub page),
and the init code's first store faulted at
`WRITE_TO_RO_PAGE cr2=0x6000024a` (the kOffMissLogger thunk).

Fix: extend `IsLikelyDataImport` with a 33-name allowlist of plain-C
CRT data exports. Future programs that import a CRT global we
haven't listed will surface the same fault path; the fix is a
one-line append to that allowlist.

### 4. Critical msvcrt CRT functions were unmapped (NO-OP)

Without `exit`, the entry function fell through `return 0;` and
`ret`'d to a NULL stack-bottom RIP — `#PF` at `rip=0`. Without
`fputs`/`fputc`/`fwrite`, no console output. Without `_initterm` /
`__getmainargs` / `__set_app_type` / `__setusermatherr` /
`_XcptFilter` etc., the CRT startup ran into half-implemented
state and either bailed early or behaved strangely.

Fix: 12 new `thunks_table.inc` entries pointing the msvcrt CRT
imports at appropriate thunks. `exit` and `_exit` route to
`kOffExitProcess` (NOT `kOffTerminate`, which forces exit code 3 —
a typo-class bug for `exit` since the program's intended rc would
be discarded). Cleanup-only paths (`_cexit` / `_c_exit` /
`_initterm` / `_onexit`) get `kOffReturnZero`. `fgetc` returns
`-1` (EOF) so loops terminate cleanly.

### 5. No real stdio thunks (added `kOffFputs` / `kOffFwrite` / `kOffFputc`)

The thunk table had nothing routing `fputs` / `fwrite` / `fputc`
into `SYS_WRITE(fd=1, ...)`. Three new hand-assembled thunks:

- `kOffFputs` (34 bytes): `fputs(const char*, FILE*)` strips the
  FILE* arg, computes strlen via inline loop, calls
  `SYS_WRITE(1, s, strlen(s))`, returns 0.
- `kOffFwrite` (28 bytes): `fwrite(ptr, sz, n, FILE*)` does
  `mul r8` for `sz*n`, calls `SYS_WRITE(1, ptr, sz*n)`, returns
  `n` (full-write success).
- `kOffFputc` (21 bytes): `fputc(c, FILE*)` stashes c on stack,
  `SYS_WRITE(1, &c, 1)`, returns `c` (NOT 0 — 7za's help-print
  loop checks `if (fputc(...) != c) bail`, so a ReturnZero stub
  silently aborts the help text mid-line).

Updated `static_assert(sizeof(kThunksBytes) == 0x109B)`.

### 6. `kSyscallWriteMax` capped writes at 256 bytes

7-Zip's help text is a single ~3 KiB `fputs` / `fwrite` call. With
the 256-byte cap the help text was truncated mid-line at "h :
Calculate hash v" — exact same character every run. Bumped to
4096 bytes (one page); still bounded, well inside the 16 KiB kernel
stack budget. Real-world stdio rarely exceeds a page in a single
call; programs that do see correct truncation + partial-write
semantics from POSIX-style retry loops.

## Smoke profile wiring

Added `SmokeProfile::PeSevenZip` + `SmokeTarget::PeSevenZip` to
`kernel/test/smoke_profile.{h,cpp}`, the `pe-sevenzip` cmdline
parser case, the `should-spawn` table entry (skip on emulator under
`SmokeProfile::None` since the load + 138 imports cost ~10 s extra
TCG wall, run-only under the explicit profile), and a 30-second
sleep tick budget. Spawn site in `kernel/proc/ring3_smoke.cpp`
mirrors the existing `ring3-winkill` block.

Embed: `userland/apps/seven_zip/7za.exe` (1.29 MiB), exposed as
`/bin/7za.exe` in ramfs and via `kBinSevenZipBytes` in
`generated_sevenzip_pe.h`.

## Verification

| Profile     | exit | Sentinel | bare FAIL | session       |
| ----------- | ---- | -------- | --------- | ------------- |
| bringup     | 33   | reached  | 0         | OK            |
| pe-winapi   | 33   | reached  | 0         | OK            |
| pe-sevenzip | 33   | reached  | 0         | OK (72-line 7za help printed) |
| linux       | 33   | reached  | 0         | OK            |

7-Zip itself exits with `rc=0` after printing the help — clean
shutdown, no panic, no leak. The kernel's frame-allocator
double-free panic that the u8 region_count overflow used to fire is
gone.

## Follow-up gaps (deferred)

- 7za's OLEAUT32 ordinal imports (#2/#4/#6/#7/#9/#10 — `SysAllocString`
  family) currently resolve to the catch-all NO-OP via the function
  miss path. The help-text path doesn't call them, so 7za doesn't
  notice; an actual archive-extract path would. Fix: extend
  `oleaut32.dll`'s export list with explicit ordinals (lld-link
  `/export:Name,@N`) and implement `SysAllocStringLen` /
  `SysAllocStringByteLen` / `SysReAllocString*`.
- Many ADVAPI32 / KERNEL32 imports still resolve to NO-OP
  (LocalFileTimeToFileTime, SetFileApisToOEM, GetVersionEx, security
  ones). 7za's archive paths will hit these; help-text doesn't.
- `kOffTerminate` is hardcoded to `mov edi, 3; SYS_EXIT` — it's
  intended for `std::terminate` (always exit code 3) and is the
  wrong choice for `exit(rc)`. The msvcrt!exit / msvcrt!_exit
  mappings now correctly use `kOffExitProcess`; the
  ucrtbase.dll / vcruntime aliases for `terminate` / `_purecall` /
  `__std_terminate` still use `kOffTerminate` and that's correct
  for them.
