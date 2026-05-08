# Win32 thunks compatibility note

> **Audience:** Contributors reading older Win32 subsystem notes
>
> **Execution context:** Documentation / code navigation
>
> **Maturity:** Stable compatibility note

## Renamed paths

Historical docs/comments may refer to `kernel/subsystems/win32/stubs.cpp`
and `kernel/subsystems/win32/stubs.h`.

Those paths were renamed to:

- `kernel/subsystems/win32/thunks.cpp`
- `kernel/subsystems/win32/thunks.h`

## How to read old references

When older notes mention `stubs.*`, treat them as references to
`thunks.*`. New code and new documentation should use the `thunks.*`
name directly.
