# Surface-coverage PE smoke suite v23 — 505 PASS, **93.7% pass rate**

Up from 93.2% in v22.

## Iteration fixes

### msvcrt.c — 3 re-exports

`memcpy` / `memmove` / `memset` re-exported from `msvcrt` (they
already live in `vcruntime140` but mingw-w64 imports them via
`msvcrt` by default; without the msvcrt-exported names, the
mingw runtime fallbacks dropped to the NO-OP catch-all).
`tools/build/build-msvcrt-dll.sh` updated to add the new export
slots.

## Cumulative

118 apps, **505 PASS**, 34 FAIL — pass rate **93.7%**.

## Files touched

- `userland/libs/msvcrt/msvcrt.c` — three new `__declspec(dllexport)` thunks.
- `tools/build/build-msvcrt-dll.sh` — export-table update.
