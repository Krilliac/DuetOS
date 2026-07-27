# Win32 PE Subsystem

> **Audience:** PE/Win32 devs, kernel hackers
>
> **Execution context:** Userland (PE process) -> int 0x80 -> kernel
>
> **Maturity:** Real third-party MSVC PEs run end-to-end

## Overview

DuetOS executes Windows PE binaries as a **first-class native ABI**.
The bytes of an MSVC-built `.exe` are mapped into a fresh address
space, relocated, IAT-patched against preloaded DuetOS userland DLLs,
and entered at the PE `EntryPoint`. The PE issues calls to the Win32
DLLs which marshal to `int 0x80` and trap into the kernel. No VM, no
emulator, no host OS underneath.

## The Layering

```
Windows PE applications
        |  imports
Win32 translator DLLs       userland/libs/   (44 production DLLs, ~1100 exports)
        |  int 0x80
Native DuetOS kernel
        |
Kernel-mode drivers (PCIe, NVMe, AHCI, USB, NIC, GPU, audio, input)
```

The Win32 DLLs are **translators**, not parallel subsystems. There is
one TCP stack in the kernel, one compositor, one VFS, one registry —
each reachable from two entry ABIs (native + Win32). See
[Subsystem Isolation](../kernel/Subsystem-Isolation.md).

## Live Verification

The serial log on every boot includes:

```
Windows Kill 1.1.4 | Windows Kill Library 3.1.3
Not enough argument. Use -h for help.
```

That is `windows-kill.exe` — a real third-party 80 KB MSVC PE with 52
imports across 6 DLLs (SEH + TLS + resources) — printing through our
PE loader, our 44 production userland DLLs (all preloaded on real
hardware; 37 production DLLs preloaded under the emulator skip-list),
our scheduler, and our syscalls.

## End-to-end Call Flow Example: `ws2_32!send`

```
PE .text:  call [__imp_send]
   -> ws2_32!send                     (translator DLL: userland/libs/ws2_32/)
   -> Win32 calling convention -> SYS_SOCK_SEND marshal
   -> int 0x80
   -> kernel syscall dispatch          kernel/syscall/syscall.cpp
   -> net stack send path              kernel/net/
   -> e1000 TX ring programming        kernel/drivers/net/e1000/
   -> packet on wire
```

The same kernel send backend is used by native sockets and Win32
sockets.

## Components

| Layer | Path | Notes |
|-------|------|-------|
| PE loader (stage 1+2) | `kernel/loader/pe_loader.cpp` | DOS + NT + PE32+ headers, sections, DIR64 reloc, IAT walk |
| EAT parser | `kernel/loader/pe_exports.cpp` | `IMAGE_EXPORT_DIRECTORY`, binary-search lookup |
| DLL loader | `kernel/loader/dll_loader.cpp` | Maps a DLL into a process, applies relocs, parses EAT |
| NT syscall dispatch | `kernel/subsystems/win32/nt_dispatch.cpp`, `nt_syscall_entry.S` | NT-call entry, routes to the generated table |
| Translator DLLs | `userland/libs/{kernel32,ntdll,user32,gdi32,...}` | 44 production DLLs, ~1100 exports |
| Flat-stubs page (legacy) | `kernel/subsystems/win32/thunks.cpp` | Fallback for anything not yet ported to a real DLL |

### Retiring the legacy thunk page

New Win32 APIs belong in the user-mode translator DLLs. The x64 PE
loader resolves those Export Address Tables before consulting the
legacy thunk table, so retirement is a row-removal operation once the
real DLL implementation is proven.

Each retirement wave is fail-closed:

1. an X-macro manifest names the APIs that require real DLL exports;
2. the kernel32 build verifies the linked AMD64 PE32+ EAT entries are
   present, non-forwarded, mapped, and executable before embedding;
3. spawn verifies the complete preload set satisfies the manifest;
4. direct kernel32/kernelbase imports and API-set contracts for a
   retired name must bind the exact verified kernel32 provider; the
   loader refuses a miss instead of using the API-set any-name
   heuristic, a miss logger, or a regenerated legacy row; and
5. a compile-time scan rejects any manifest name restored to
   `thunks_table.inc`.

The first wave moved `CreateThread`, `ExitThread`,
`FreeLibraryAndExitThread`, and `GetExitCodeThread`. It also fixed the
old `FreeLibraryAndExitThread` alias, which consumed the module handle
in RCX as the exit code instead of the second argument in RDX.
The second wave moved `GetCurrentProcess`, `GetCurrentThread`,
`GetCurrentProcessId`, `GetCurrentThreadId`, `GetLastError`, and
`SetLastError`. Direct kernelbase imports and API-set aliases of these
retired names converge on the verified kernel32 provider; they cannot
fall through to their former fixed-offset thunk entries.
The third wave moved `InterlockedExchangeAdd`, `InterlockedAnd`,
`InterlockedOr`, and `InterlockedXor`. A mixed-provider fixture binds
them through kernelbase and the interlocked API-set contract, validates
returned-old and final values, and joins two contending add workers.
The underscored vcruntime intrinsic, 64-bit variants, and fixed
bytecode layout remain deliberately unchanged.
PE32 uses its separate i386 companion DLL and unresolved-import
gateway, so it is intentionally outside this x64 retirement policy.
For PE32+, a kernel32/kernelbase/API-set ordinal import may bind a real
preloaded EAT ordinal, but an ordinal miss is fatal: `#<ordinal>` has no
trustworthy name for either the manifest or the legacy table and must
not become a success-returning generic miss thunk.

The fixed mapping cannot disappear yet: a naturally returning Win32
thread still enters `ThreadExitTramp` at offset `0x8A6`, and unresolved
imports still use diagnostic gateways. Dead per-API byte ranges are
left in place until a separate offset-compaction wave can prove every
live absolute gateway.

The emulator-safe regression coverage is split by workload:
`smoke=pe-threads` runs the natural-return and explicit-exit thread PEs,
requires the thread and bitwise-atomic imports to log `via-dll`, and
checks the corrected combined free-and-exit argument contract.
`smoke=pe-winapi` asserts the ten wave-2/3 identity, error, and atomic
contracts and requires their `via-dll` bindings. Its
`thunk_alias_smoke` PE deliberately splits the ten imports across
kernel32, kernelbase, and three API-set descriptors. It validates the
atomic returned-old/final values and a joined 131,072-operation
contention total, so provider convergence and semantics are both
covered by the emulator gate.

### NT syscall handlers (17 `*_syscall.cpp` TUs)

Each TU owns one resource family; the kernel routes each `SYS_*`
through the relevant TU. One subsystem per file (CLAUDE.md rule):

| TU | Resource family |
|----|-----------------|
| `file_syscall.cpp` | File create/read/write/seek/close, attributes |
| `dir_syscall.cpp` | Directory enumeration |
| `heap_syscall.cpp` | Per-process heap arena (`SYS_HEAP_*`) |
| `thread_syscall.cpp` | Thread create/exit/suspend/resume |
| `mutex_syscall.cpp` | Kernel mutex objects |
| `event_syscall.cpp` | Kernel event objects |
| `semaphore_syscall.cpp` | Kernel semaphore objects |
| `iocp_syscall.cpp` | I/O completion ports (KObject `IocpPort` + `kobj_handles`) |
| `job_syscall.cpp` | Job objects |
| `pipe_syscall.cpp` | Anonymous pipes |
| `named_pipe_syscall.cpp` | Named pipes |
| `named_kobj_syscall.cpp` | Named kernel objects (open-by-name) |
| `tls_syscall.cpp` | Thread-local storage slots |
| `spawn_syscall.cpp` | Process spawn |
| `window_syscall.cpp` | Window/message surface (`SYS_WIN_*`) |
| `apc_syscall.cpp` | Asynchronous procedure calls |
| `waitaddr_syscall.cpp` | `WaitOnAddress` / `WakeByAddress` futex shape |
| `token_syscall.cpp` | Token / privilege facade (probe-satisfying, see below) |
| `vmap_syscall.cpp` | User virtual-memory mapping |

Supporting handlers in the same directory: `proc_env.cpp` (per-process
environment / command-line page the CRT reads at startup),
`section.cpp` (section / memory-mapped-file objects), and
`registry.cpp` + `registry_hive.cpp` (the registry tree —
see [Win32 Registry](Win32-Registry.md)).

### SEH unwind model

Structured Exception Handling is load-bearing — `windows-kill.exe`
and other real MSVC PEs install SEH frames. The dispatcher lives in
`kernel/subsystems/win32/seh_dispatch.cpp` with the unwind trampoline
in `seh_unwind.S`: a faulting PE thread's trap is converted into an
`EXCEPTION_RECORD`, the registered `__C_specific_handler` /
language-specific handlers are walked, and control is unwound to the
selected handler frame (or the process is killed if none claims it).
This is what lets a PE's `__try`/`__except` actually catch a fault
raised inside our syscall path.

### NT coverage figure

`kernel/subsystems/win32/nt_coverage.cpp` prints a boot-log
scoreboard from the generated tables in
`nt_syscall_table_generated.h`: **50 / 292 bedrock NT calls**
(present on every Windows XP→Win11 build) are wired to a DuetOS
syscall, against a **489-entry full table** of every NT syscall
known on the target Windows version. See
[`Win32-Surface-Status` §11](../reference/Win32-Surface-Status.md).

## Per-process Bringup

When a PE spawns:

1. PE bytes validated; `PeReport` summarises every directory.
2. New `mm::AddressSpace` allocated.
3. **Preload set:** all 44 production DLLs in `userland/libs/` (plus
   2 `customdll*` test fixtures) mapped into the new AS on real
   hardware. Under `arch::IsEmulator()` the 9 entries flagged
   `essential=false` (7 production DLLs + 2 fixtures) are skipped to
   keep CI runs short; the 37 essential production entries always
   map. No on-demand `LoadLibraryA/W` path is wired today.
4. PE sections mapped with characteristic-driven flags (W^X enforced).
5. DIR64 base relocations applied.
6. Imports walked: each `(dll, name)` resolved against the preloaded
   set's EATs, IAT slots patched. Forwarders chase recursively
   (name-form + ordinal-form `Dll.#N`). By-ordinal IAT entries
   resolve against preloaded EATs.
7. Process + thread state created, heap bootstrapped.
8. First user thread enters at `ImageBase + AddressOfEntryPoint`.

Per-process cost: ~96 frames for the preloaded DLL set.

## What Works Today

- **Freestanding Win32 PEs** (no CRT, direct `int 0x80`) — since
  Phase 1.
- **MSVC console PEs with CRT**: threads, mutexes, events, atomics,
  printf, file I/O, registry queries — since Phase 4 / 5.
- **`windows-kill.exe`** (real shipped third-party Windows binary) —
  since the end of Phase 3.
- **`unity_engine.exe`** (real Unity 2022 LTS standalone launcher)
  ran end-to-end during Phase 5 — 72 imports across KERNEL32.dll
  + UnityPlayer.dll resolved cleanly, CRT bootstrap walked
  PEB + PEB_LDR_DATA (set up by the PE loader's TEB scaffolding),
  `UnityMain2` returned through the catch-all NO-OP, process
  exited `rc=0` with no #PF or task-kill. The binary itself
  was vendored at that time but has since been removed
  (no-vendored-binaries policy, commit ceaf972) — the loader
  fixes it forced through stay in tree and the same
  invocation works against a binary the operator drops into
  FAT32 `/lib/` at boot.
- **Windowed Win32 PEs** (`windowed_hello`) — Phase 6, end-to-end on
  every boot.
- **Live Internet** (DNS + TCP to a real Internet host) — Phase 6.

See [History](../getting-started/History.md) for the full evolution.

## What Doesn't Work (Yet)

- **COM apartments**, real `CoInitialize` / `CoCreateInstance`.
- **DirectX rendering** beyond Clear + Present (`Draw*` returns
  `E_NOTIMPL`).
- **Common controls, scroll bars, outline fonts, multi-threaded
  message queues**.
- **Most of `winsock2`'s asynchronous surface** (synchronous BSD
  socket subset works).
- **Arbitrary file writes** through the FS write paths.

## Threading & Locking Model

A PE process runs as ordinary DuetOS user threads on the per-CPU
scheduler — there is no Win32-private scheduler. Win32 sync
primitives map to kernel objects: `mutex_syscall.cpp`,
`event_syscall.cpp`, `semaphore_syscall.cpp`, and the
`waitaddr_syscall.cpp` futex shape back `WaitForSingleObject` /
`SetEvent` / `WaitOnAddress`. User-mode critical sections /
SRW / InitOnce spin-CAS in the DLL and fall back to `SYS_YIELD`.
The NT syscall handlers run in kernel/process context behind the
`int 0x80` trap; they take the same kernel locks as the native
ABI (one VFS lock, one registry lock, one window-manager lock) —
the Win32 front-end adds no parallel locking.

## Capability / Privilege Surface

A PE binary has exactly the effective capabilities in its locked
Process authority snapshot — durable caps plus unexpired broker
leases, bounded by its monotonic ceiling. Nothing the Win32 ABI shape
implies grants authority. Every effect crosses a cap-gated syscall: a write needs
`kCapFsWrite` (`SYS_FILE_WRITE`), a spawn needs `kCapSpawnThread`
(`SYS_THREAD_CREATE`), and so on. The token / privilege handler
(`token_syscall.cpp`) and the Win32 privilege APIs above it
(`NtAdjustPrivilegesToken`, `SeDebugPrivilege`, integrity levels,
ACLs) remain cosmetic except for the mapped
`NtAdjustPrivilegesToken` path: mapped privilege enablement may request
a bounded broker lease, disablement clears live authority, and
`SE_PRIVILEGE_REMOVED` permanently lowers the Process ceiling. Kernel
capability helpers and syscall gates remain the only authority. See
[`security/Capabilities.md`](../security/Capabilities.md) and
[Subsystem Isolation](../kernel/Subsystem-Isolation.md).

> The reviewable signal: could a malicious PE use a Win32 path to
> do something a native DuetOS process with the same caps could
> not? If yes, the gate is wrong, not the workload.

**Heap free-list hardening.** The Win32 user-heap arena is
guest-writable, so its in-band `next` pointers are attacker-controlled.
`Win32HeapAllocOnBinding` (`subsystems/win32/heap.cpp`) now validates
every `cur`/`prev` block link against `[base_va, heap_end - header)` and
8-byte alignment before dereferencing — the same bound `…FreeOnBinding`
already used — and `PeekU64`/`PokeU64` reject any access that would cross
a page boundary, so a forged link can no longer spill an 8-byte read/
write into the adjacent kernel direct-map frame. (Security audit SEC-005,
CWE-787, 2026-06-07.)

## Related Pages

- [PE Loader](PE-Loader.md)
- [Win32 DLLs](Win32-DLLs.md)
- [DirectX v0 Path](DirectX.md)
- [Compositor and Window Manager](Compositor.md)
- [Linux ABI](Linux-ABI.md)
- [Subsystem Isolation](../kernel/Subsystem-Isolation.md)
- [Win32 Thunks Compat Note](../advanced/Win32-Thunks-Compat-Note.md)
