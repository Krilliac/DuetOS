# Syscalls

> **Audience:** Kernel hackers, ABI consumers, PE/Linux thunk authors
>
> **Execution context:** Userland -> kernel via `int 0x80`
>
> **Maturity:** ABI commitment — once published, syscall numbers are forever

## Overview

DuetOS uses `int 0x80` as the single native syscall gate. There are
~57 numbered calls today (`SYS_*`). Both native binaries and the Win32
translator DLL surface marshal into this same gate.

## Calling Convention

| Register | Meaning |
|----------|---------|
| `rax` | syscall number on entry; return value on exit |
| `rdi` | arg1 |
| `rsi` | arg2 |
| `rdx` | arg3 |
| `r10` | arg4 (NOT `rcx` — `rcx` is clobbered by `syscall`/`int`) |
| `r8`  | arg5 |
| `r9`  | arg6 |

```
user call site
  -> marshal args to (rdi, rsi, rdx, r10, r8, r9)
  -> rax = SYS_*
  -> int 0x80
  -> kernel dispatch table
  -> subsystem handler
  -> retval in rax
```

## Source of Truth

- `kernel/syscall/syscall.cpp` — `int 0x80` entry, dispatcher
- `kernel/syscall/syscall_names.def` — numbered syscall list (X-macros)
- `kernel/syscall/syscall_names.cpp` — name lookup
- `kernel/syscall/cap_table.def` — which capability bit each syscall
  requires (X-macros)
- `kernel/syscall/cap_gate.cpp` — capability gate

The X-macro headers (`*.def`) are the canonical list — `docs/sync-wiki.sh`
reads them to populate the [Syscall ABI specification](../specifications/Syscall-ABI.md).

## Capability Gating

Every privileged syscall checks `CurrentProcess()->caps` against a
named capability bit before executing. Denials log
`[sys] denied syscall=<NAME> pid=<P> cap=<NAME>` and return `-1` to
user mode. Unprivileged syscalls (`SYS_GETPID`, `SYS_YIELD`, `SYS_EXIT`)
run unchecked.

See [Capabilities](../security/Capabilities.md) for the cap inventory
and gating model.

## ABI Stability

Syscall numbers are **ABI commitments once published**. Rules:

1. Always add at the end of `syscall_names.def`. Never reuse a retired
   number — leave it as a deprecated stub if you must remove it.
2. Argument order in the registers above is part of the ABI too.
3. Return-value convention (negative on failure, zero or positive
   value on success) is part of the ABI.
4. The capability bit a syscall checks is part of the ABI for any
   process image that ships a "requested caps" manifest.

Treat any change to these as you would a change to a published shared
library's symbol set.

## Win32 Translator Path

A Win32 PE imports `ws2_32!send`. The DLL's `send` adapts the Win32
calling convention (`rcx, rdx, r8, r9`) to the DuetOS one
(`rdi, rsi, rdx, r10`), sets `rax = SYS_SOCK_SEND`, and issues
`int 0x80`. The kernel-side handler is identical to the one a native
DuetOS process would hit. See
[Win32 PE Subsystem](../subsystems/Win32-PE-Subsystem.md).

## Time Syscalls

`kernel/syscall/time_syscall.cpp` houses the time-related syscalls
(`SYS_GET_TICKS`, `SYS_GET_FILETIME` analogues, etc.) and is split out
from the main dispatcher for clarity.

## Related Pages

- [Syscall ABI specification](../specifications/Syscall-ABI.md) — full
  numbered list (auto-synced)
- [Capabilities](../security/Capabilities.md)
- [Subsystem Isolation](Subsystem-Isolation.md)
- [Win32 PE Subsystem](../subsystems/Win32-PE-Subsystem.md)
