# DuetOS — architecture

For the evolution story, see [`HISTORY.md`](HISTORY.md). This document is
the layering model — what calls what, who owns which subsystem, and how
Windows binaries actually run.

---

## One stack, two ABIs

DuetOS is **not** two parallel operating systems. It is one kernel
with one set of drivers and one real implementation of each subsystem,
reachable from ring 3 through two ABIs:

1. **Native ABI** — `int 0x80`, `SYS_*` numbers. The primary path.
2. **Win32 ABI** — `call qword [iat]` through a patched Import
   Address Table, resolved to user-mode DLL code that forwards to the
   native ABI.

```
┌──────────────────────────────────────────────────────────────┐
│  Windows PE applications                                       │
│  third-party .exe files, unmodified                            │
└──────────────────────────────────────────────────────────────┘
                │ imports:  kernel32!CreateFileW
                │           ws2_32!socket
                │           user32!CreateWindowExW
                ↓
┌──────────────────────────────────────────────────────────────┐
│  Win32 translator DLLs  (userland/libs/*/, 29 DLLs)            │
│  These are NOT reimplementations of Windows subsystems.        │
│  They are thin marshallers: Win32 ABI → native SYS_*.          │
└──────────────────────────────────────────────────────────────┘
                │ int 0x80
                │ rax = SYS_* number
                │ rdi / rsi / rdx / r10 / r8 / r9 = args
                ↓
┌──────────────────────────────────────────────────────────────┐
│  Native DuetOS kernel                                         │
│  One TCP stack. One compositor. One FS VFS. One registry.      │
│  One GPU ICD. One scheduler. No "Windows parallels."           │
└──────────────────────────────────────────────────────────────┘
                │
                ↓
┌──────────────────────────────────────────────────────────────┐
│  Kernel-mode drivers                                           │
│  PCIe, NVMe, AHCI, xHCI, e1000, iwlwifi, HDA,                 │
│  Intel iGPU, AMDGPU, NVIDIA                                    │
└──────────────────────────────────────────────────────────────┘
```

---

## Win32 DLLs are translators, not subsystems

The commitment: every Win32 DLL in `userland/libs/` is a translator.
It takes a Win32 ABI call, marshals arguments, and hands off to the
native kernel for the actual work. There is no separate "Windows TCP
stack" or "Windows compositor" — just our one stack reached from two
entry points.

A call like this:

```c
// In a Windows PE built with MSVC:
send(sock, buf, len, 0);
```

Travels as follows:

1. The PE's `.text` does `call qword ptr [__imp_send]`.
2. The IAT slot was patched at load time to point at our
   `userland/libs/ws2_32/ws2_32.c:send` — which was itself resolved
   via slice-6's via-DLL path through the preloaded DLL table.
3. `ws2_32!send` translates the Winsock ABI (rcx=sock, rdx=buf, r8=len,
   r9=flags) into native ABI (rdi=sock, rsi=buf, rdx=len, r10=flags)
   and issues `int 0x80` with `rax = SYS_SOCK_SEND`.
4. The kernel's `SYS_SOCK_SEND` dispatcher in `kernel/core/syscall.cpp`
   looks up the `core::Socket` by fd and hands the buffer to
   `net::stack::Send`.
5. The net stack queues the TCP segment, hands it to the e1000 kernel
   driver, which writes the TX ring and lets the NIC DMA out.

There is one and only one TCP stack at step 4. A native program calling
`socket()` via the DuetOS syscall directly hits the same stack at the
same entry point.

The same pattern applies to:

- **Graphics** — `d3d11!CreateDevice` translates D3D → our Vulkan ICD
  (same shape as [DXVK](https://github.com/doitsujin/dxvk) on Linux,
  re-implemented from spec).
- **File I/O** — `kernel32!CreateFileW` → `SYS_FILE_OPEN` →
  our VFS.
- **Registry** — implemented fully in `userland/libs/advapi32/`
  because the data is small and static; no kernel backing needed.
- **Threads / mutexes / events** — `kernel32!CreateThread` →
  `SYS_THREAD_CREATE` → our scheduler.

---

## Where real implementations currently live

| Subsystem | Kernel backend | Win32 translator state |
|-----------|----------------|-----------------------|
| File I/O | ramfs + FAT32 (read) + `SYS_FILE_*` | **working** — `fopen`/`fread` live-verified |
| Registry | static tree in `advapi32` | **working** — `RegQueryValueEx` live-verified |
| stdout / stderr | COM1 serial | **working** — `printf` live-verified |
| Time | HPET + LAPIC timer | **working** — `GetTickCount` / `QueryPerf*` |
| Heap | kernel slab + per-process region | **working** — `malloc` / `HeapAlloc` |
| Threads | SMP round-robin scheduler | **working** — `CreateThread` + `Wait*` |
| Atomics | native `lock xadd` / `cmpxchg` | **working** — full `Interlocked*` |
| Critical sections + SRW | CAS + `SYS_YIELD` spin | **working** |
| Environment vars | static list in `ucrtbase` | **working** — `getenv` |
| stdin | PS/2 keyboard driver exists, not wired to `fread` yet | **stub** — `fgets` returns NULL |
| Network | kernel stack is skeleton | **stub** — `ws2_32` returns WSAENETDOWN |
| Graphics | framebuffer + compositor; no Vulkan ICD yet | **stub** — `d3d*` returns E_NOTIMPL |
| Windows / input | no WM, no HWND | **stub** — `user32!CreateWindow` returns NULL |
| Audio | no audio path | **stub** — `winmm!PlaySound` returns 0 |
| COM runtime | none | **stub** — `CoCreateInstance` returns CLASS_E_... |

Every row with **working** in the translator column has a real kernel
backend. Every row with **stub** is where the native kernel implementation
hasn't been built yet; the translator DLL returns the documented Windows
error code so calling programs see clean failure paths instead of
page faults.

---

## The DLL load path

How a Win32 PE gets its imports resolved:

1. `SpawnPeFile` is called with a PE byte buffer and capability set.
2. `PeValidate` → `PeReport` (diagnostic dump) → decide to load.
3. `AddressSpaceCreate` allocates a fresh PML4.
4. Before `PeLoad` runs, the spawn code pre-loads the 29-DLL set into
   the new AS via `DllLoad`. Each DLL gets its own load base (starting
   at `0x10000000`, spaced 1 MiB apart) and its EAT is parsed into a
   `DllImage`.
5. `PeLoad` is called with the `DllImage*` array. It:
   - Maps the PE's sections at their `ImageBase + VirtualAddress`.
   - Applies base relocations.
   - Walks the Import Directory. For each `{dll, func}` pair,
     `TryResolveViaPreloadedDlls` searches the DLL array and, on hit,
     patches the IAT slot with the export's absolute VA. Forwarder
     exports recurse up to depth 4.
   - Falls through to the legacy flat stubs table for anything not
     covered by the preloaded DLLs.
6. `ProcessCreate` + `Win32HeapInit` + `ProcessRegisterDllImage` for
   each preloaded DLL (so `SYS_DLL_PROC_ADDRESS` can reach them).
7. `SchedCreateUser` puts the task on a runqueue. On its first tick,
   it enters ring 3 at `ImageBase + AddressOfEntryPoint` with a
   Win32-shaped rsp.

---

## Native syscall ABI

All syscalls go through `int 0x80`. The dispatcher is
`kernel/core/syscall.cpp :: SyscallDispatch`. Arguments follow the
System V AMD64 convention adapted for 6 args:

| Register | Role |
|----------|------|
| `rax` | Syscall number (on entry); return value (on exit) |
| `rdi` | arg1 |
| `rsi` | arg2 |
| `rdx` | arg3 |
| `r10` | arg4 |
| `r8` | arg5 |
| `r9` | arg6 |

The kernel preserves all registers except `rax`. `rcx` and `r11` are
NOT used as arg registers (they collide with `syscall`/`sysret`);
we use `int 0x80` so this is an internal constraint only.

Full syscall table lives in `kernel/core/syscall.h`. As of this
writing, ~57 numbered syscalls cover exit, yield, pid queries, last-
error, heap, file I/O, file-handle ops, timer, event / mutex /
semaphore / thread primitives, TLS slots, vmap, debug print, and NT
forwarding (`SYS_NT_INVOKE`).

---

## Capabilities, not uid

Every `Process` has a `CapSet` — a bitmask of capabilities granted at
spawn time. Examples: `kCapSerialConsole`, `kCapFsRead`, `kCapFsWrite`,
`kCapDebug`, `kCapSpawnThread`. Syscalls that touch sensitive state
check the caller's CapSet and return `-1` on miss.

There is no setuid. A process can drop caps (`SYS_DROPCAPS`), never
grant them. The Win32 handle model (explicitly-granted, revocable,
duplicatable) maps onto this cleanly.

Trusted kernel-shipped PEs run with the full CapSet. Adversarial
probes run with empty CapSets — each denied syscall is logged and
counted; threshold-crossing processes are reaped.

---

## Security posture

- **W^X** enforced at page-map time: no user mapping may be both
  writable and executable. Enforcement lives in
  `mm::AddressSpaceMapUserPage`.
- **SMEP + SMAP** enabled at boot (CPUID-gated CR4 flips).
- **ASLR**: per-spawn 64 KiB-aligned delta in `[0, 64 MiB)` added to
  PE `ImageBase`.
- **Stack canaries** on every kernel function with a stack frame.
- **Retpoline** on kernel indirect calls.
- **Frame budgets**: every `AddressSpace` has a capped region count;
  a runaway process can't drain the frame allocator.
- **Kernel-stack guard pages**: unmapped low-edge page per task.

---

## Build + run

```bash
# Configure
cmake --preset x86_64-debug

# Build kernel + all userland DLLs + ISO
cmake --build build/x86_64-debug --parallel $(nproc)

# Boot in QEMU (requires qemu-system-x86 + OVMF + xorriso +
# grub-common + grub-pc-bin + grub-efi-amd64-bin + mtools).
DUETOS_TIMEOUT=30 tools/qemu/run.sh build/x86_64-debug/duetos.iso
```

The boot log comes out on stdout. On a healthy boot you see the DLL
preload dump, per-PE spawn records, import-resolution traces, and the
exit codes of each test fixture. The end-to-end sentinel to look for
is `[reg-fopen-test] all checks passed` — that means the real
registry, the real `fopen`, and the real `printf` formatting all
work together under live execution.

---

## Project pillars (non-negotiable)

From `CLAUDE.md`:

- Run Windows PE executables natively. Not a VM. Not Wine.
- Run on commodity PC hardware. x86_64 first class from day one.
- Capability-based IPC. No setuid.
- W^X enforced. ASLR enforced. CFI enforced.
- Vulkan is the primary user-mode graphics API; D3D translates onto it.
- One subsystem per function; two translators (native + Win32) on top.

Every architectural decision in the tree ultimately traces to one of
those.
