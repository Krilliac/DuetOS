# Surface-coverage PE smoke suite v18 — 118 apps, 452 PASS, **87.3% pass rate**

**Pass rate: 87.3%** (up from 83.4% in v17, 79.2% in v15).

## Iteration fixes (kernel32 + msvcrt)

### kernel32.c — 21 new exports

- `GetUserDefaultUILanguage` / `GetSystemDefaultUILanguage` (en-US 0x409)
- `SetConsoleTitleA/W` + `GetConsoleTitleA/W` — in-memory state
- `FoldStringW` — pass-through
- `GetCurrencyFormatA` — prefix "$"
- `OpenThread` — return current-thread pseudo-handle
- `GetPhysicallyInstalledSystemMemory` — 8 GB
- `HeapValidate` — TRUE
- `GetProcessHeaps` — return 1 entry (process heap)
- `DuplicateHandle` — alias src to dst
- `GetHandleInformation` / `SetHandleInformation` — TRUE
- `QueryProcessCycleTime` / `QueryThreadCycleTime` — read RDTSC
- `GetFileTime` — canned 2026-01-01 epoch
- `GetFileInformationByHandle` — fill 52-byte struct

### msvcrt.c — 8 new exports

- `mbstowcs` / `wcstombs` — byte-cast
- `_wtoi` / `_wtol` / `_wtoll` — wide-char number parsing
- `wcstol` / `wcstoul`
- `_getmbcp` — return CP 1252

## Per-app gains

| App | v17 | v18 | Δ |
|---|---|---|---|
| nls | 4/2 | 6/0 | +2 |
| handle2 | 2/2 | 4/0 | +2 |
| heap | 5/2 | 7/0 | +2 |
| perf | 4/2 | 6/0 | +2 |
| sysinfo | 2/2 | 3/1 | +1 |
| fs2 | 4/2 | 6/0 | +2 |
| thread3 | 3/1 | 4/1 | +1 |
| locale2 | 0/4 | 4/0 | +4 |
| wstr2 | 0/2 | 4/0 | +4 |
| mbcs | 1/2 | 3/0 | +2 |
| console | 5/2 | 7/0 | +2 |

**+24 PASS** from these iteration fixes.

## Cumulative

118 apps, **452 PASS**, 66 FAIL — pass rate ≈ **87.3%**.
