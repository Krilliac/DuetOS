# Surface-coverage PE smoke suite v21 — 502 PASS, **92.4% pass rate**

## Iteration fixes

### kernel32.c — 7 new exports
- `CheckRemoteDebuggerPresent` (FALSE)
- `GetProcessId` / `GetThreadId` — pseudo-handle resolution via SYS_GETPID/TID
- `AddVectoredExceptionHandler` / `RemoveVectoredExceptionHandler` — sentinel
- `GetThreadPriorityBoost`
- `GetConsoleProcessList` (1 entry)

### shlwapi.c — 4 new exports
- `PathCanonicalizeW` — collapse "..".
- `PathRenameExtensionW`
- `PathQuoteSpacesW` / `PathUnquoteSpacesW`

## Cumulative

118 apps, **502 PASS**, 41 FAIL — pass rate **92.4%**.
