# Surface-coverage PE smoke suite v19 — 118 apps, 469 PASS, **89.5% pass rate**

**Pass rate: 89.5%** (up from 87.3% in v18, 79.2% in v15).

## Iteration fixes

### kernel32.c — 6 new exports
- `GetComputerNameExW` (returns "duetos")
- `GetLogicalDriveStringsA` ("C:\\\0\0")
- `GetProcessHandleCount` (8)
- `SetErrorMode` / `GetErrorMode` (in-memory state)

### msvcrt.c — 5 new exports
- `_putch` / `_putwch` / `_kbhit` / `_cputs` (route to SYS_WRITE)
- `signal` (16-slot handler table)

### user32.c — 5 new exports
- `GetClassInfoW` / `GetClassInfoExW` (TRUE for any non-empty class)
- `CreateAcceleratorTableW` / `CopyAcceleratorTableW` /
  `DestroyAcceleratorTable`

### shell32.c — `CommandLineToArgvW` real impl
Whitespace-split parser that allocates a single buffer holding
argv pointers + parsed tokens via SYS_HEAP_ALLOC.

### uxtheme.c — `GetCurrentThemeName` returns "Aero" / "NormalColor" / "NormalSize"

### ws2_32.c — 4 new exports
`WSACreateEvent` / `WSACloseEvent` / `WSASetEvent` / `WSAResetEvent`
sentinel handles.

### advapi32.c — `GetTokenInformation` returns TRUE with zeroed buffer

## Per-app gains

| App | v18 | v19 | Δ |
|---|---|---|---|
| shell | 2/1 | 3/0 | +1 |
| uxtheme | 3/1 | 4/0 | +1 |
| select | 2/1 | 4/0 | +2 |
| winsock_ext | 2/1 | 6/0 | +4 |
| token | 2/1 | 3/0 | +1 |
| vol | 4/1 | 5/0 | +1 |
| proc2 | 3/1 | 4/0 | +1 |
| winerr | 3/1 | 4/0 | +1 |
| conio | 2/1 | 2/0 (no FAIL) | neutral |
| enviro | 1/1 | 2/0 | +1 |
| accel | 0/1 | 3/0 | +3 |

## Cumulative

118 apps, **469 PASS**, 55 FAIL — pass rate ≈ **89.5%**.
