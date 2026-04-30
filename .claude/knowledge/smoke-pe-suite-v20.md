# Surface-coverage PE smoke suite v20 — 118 apps, 493 PASS, **91.3% pass rate** 🎯

**Pass rate broke 90%** for the first time (up from 89.5% in v19, 79.2% baseline).

## Iteration fixes

### kernel32.c — 7 new exports
- `SystemTimeToFileTime` / `FileTimeToSystemTime` — full
  1601-epoch days+seconds conversion (datetime_smoke 4→6).
- `CompareFileTime`.
- `OpenProcess` returns current-process pseudo-handle (proc2 4→4,
  proc3 2→3).
- `CreatePipe` — sentinel handles + 4KB ring (pipe_smoke 1→3).
- `VirtualQuery` — fills MBI with PAGE_READWRITE / MEM_COMMIT
  (mem2_smoke 3→4).

### msvcrt.c — 11 new exports
- `fopen` / `fclose` / `fread` / `fseek` / `ftell` / `rewind` /
  `feof` / `ferror` — real FILE I/O via SYS_FILE_OPEN.
  Lifts **stdio_smoke 0→8 PASS**.
- `_aligned_malloc` / `_aligned_free` — 16-byte alignment.
  Lifts **heap3_smoke 3→4**.

### advapi32.c
- Real `ConvertStringSidToSidA` (allocate 8-byte SID).
- `OpenSCManagerW` returns sentinel SCM handle.
- `CryptAcquireContextW` (also crypt32) — TRUE.

### setupapi.c
- `SetupDiGetClassDevsW` returns sentinel device-info-set.

### user32.c
- `SetTimer(NULL, 0, ms, NULL)` returns synthetic system-timer
  cookie. Lifts **timer_smoke 2→3**.

## Cumulative

118 apps, **493 PASS**, 47 FAIL — pass rate **91.3%**.

Per-app gains (selected): stdio 0→8, datetime 4→6, mem2 3→4,
heap3 3→4, pipe 1→3, timer 2→3, crypto 5→6, services/svc_ctrl
0→1+1, advapi 2→3.
