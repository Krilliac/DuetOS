# Surface-coverage PE smoke suite v22 — 505 PASS, **93.2% pass rate**

Up from 92.4% in v21. 

## Iteration fixes
- ole32: `StringFromGUID2` real impl
- user32: `GetDpiForSystem` / `GetDpiForWindow` (returns 96)
- kernel32: `GetMaximumProcessorCount` (1)
- advapi32: `CryptGenRandom` bridge to `SystemFunction036`

## Cumulative
118 apps, **505 PASS**, 37 FAIL — pass rate **93.2%**.
