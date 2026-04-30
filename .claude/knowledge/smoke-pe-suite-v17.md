# Surface-coverage PE smoke suite v17 — 118 apps, 432 PASS Win32 APIs

**Pass rate: 83.4%** (up from 81.4% in v16, 79.2% in v15).

## Iteration fixes

### user32 multimon (multimon_smoke 2→5 = +3 PASS)

- `EnumDisplayMonitors`, `MonitorFromPoint`, `MonitorFromWindow`,
  `GetMonitorInfoW`, `EnumDisplayDevicesW`, `EnumDisplaySettingsW`
  — single-monitor sentinel impls. Six new exports.

### gdi32 (gdi_smoke 2→6 = +4 PASS)

- `CreateCompatibleBitmap` returns sentinel handle.
- `GetStockObject` returns idx-keyed sentinel.
- `SelectObject` returns non-NULL "previous" sentinel.

### user32 DDEML (dde_smoke 1→4 = +3 PASS)

- `DdeInitializeA/W` returns 0xDDE10001 instance + DMLERR_NO_ERROR.
- `DdeCreateStringHandleA/W` allocates 32-bit counter handles.
- `DdeFreeStringHandle` + `DdeUninitialize` succeed. Six exports.

### advapi32 RegOpen with empty subkey (reg2_smoke setup)

- Empty subkey on a predefined HKEY → return the root handle.
  Lifts the HKLM/HKCU/HKU/HKCR root open paths.

### Preload flips (essential=true)

- `userenv.dll` (userenv_smoke 1→3)
- `shell32.dll` (shell_smoke +)
- `setupapi.dll`

## Cumulative

118 apps, 432 PASS, 86 FAIL — pass rate ≈ 83.4%.
