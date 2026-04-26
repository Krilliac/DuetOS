# DuetOS — Architecture Deep Dive

For the evolution timeline, see [`HISTORY.md`](HISTORY.md). This document is the system map: what exists today, how the major components interact, and where each ABI enters the same core runtime.

---

## 0) Executive model (one kernel, two user ABI faces)

DuetOS is one operating system with one kernel and one set of core backends. It exposes two user entry surfaces:

- **Native DuetOS ABI** (`int 0x80`, `SYS_*` numbers)
- **Win32 ABI** (PE imports resolved to DuetOS user-mode translator DLLs)

Both paths converge into the same kernel subsystems.

```text
                 ┌─────────────────────────────────────────────────────┐
                 │                  User Programs                      │
                 │                                                     │
                 │  A) Native DuetOS apps      B) Windows PE apps     │
                 └───────────────┬───────────────────┬─────────────────┘
                                 │                   │
                                 │                   │ IAT calls
                                 │                   │ (kernel32/user32/ws2_32/...)
                                 │                   ▼
                                 │        ┌────────────────────────────┐
                                 │        │ Win32 Translator DLL Layer │
                                 │        │ (userland/libs/*)          │
                                 │        │ Win32 ABI -> SYS_* marshal │
                                 │        └──────────────┬─────────────┘
                                 │                       │
                                 └───────────┬───────────┘
                                             │  int 0x80
                                             ▼
                    ┌───────────────────────────────────────────────────┐
                    │                DuetOS Kernel Core                │
                    │  sched | mm | vfs | net | graphics | ipc | ...  │
                    └───────────────────────────┬───────────────────────┘
                                                │
                                                ▼
                    ┌───────────────────────────────────────────────────┐
                    │               Kernel Device Drivers              │
                    │ PCIe, NVMe, AHCI, xHCI, e1000, virtio-gpu, ...  │
                    └───────────────────────────────────────────────────┘
```

**Design invariant:** no duplicate subsystem stacks (no separate “Windows TCP stack”, no separate “Windows VFS”). There is only one implementation per domain, shared by both ABI fronts.

---

## 1) Boot and bring-up choreography (what starts first, and why)

```text
[UEFI firmware]
      |
      v
[bootloader / kernel image handoff]
      |
      v
[kernel entry (x86_64)]
      |
      +--> early serial console
      +--> memory map ingest
      +--> paging + higher-half mappings
      +--> frame allocator + kernel heap
      +--> GDT/IDT + exception/trap plumbing
      +--> LAPIC/IOAPIC/timer setup
      +--> scheduler online
      +--> core driver init (PCI -> storage/net/input/gpu)
      +--> VFS mount roots + process/runtime services
      +--> user-mode workloads (native + PE fixtures)
```

### Bring-up dependency chain

```text
MMU before scheduler context switches
-> scheduler before user threads
-> PCI enumeration before device-class probes
-> block/network/input before higher services
-> core services before Win32 translator workloads
```

The ordering is intentionally strict to prevent partially-live subsystems from exposing unstable ABI behavior.

---

## 2) Architectural layers and ownership

### Layered view

```text
┌────────────────────────────────────────────────────────────────────────────┐
│ L6: Applications                                                          │
│     - Native apps                                                         │
│     - Windows PE executables                                              │
├────────────────────────────────────────────────────────────────────────────┤
│ L5: User ABI/adaptation libraries                                         │
│     - Native libc surface                                                 │
│     - Win32 translators: ntdll/kernel32/user32/gdi32/ws2_32/...          │
├────────────────────────────────────────────────────────────────────────────┤
│ L4: Syscall contract                                                      │
│     - int 0x80 entry                                                      │
│     - SYS_* numbering (ABI-stable once published)                         │
├────────────────────────────────────────────────────────────────────────────┤
│ L3: Kernel subsystems                                                     │
│     - Scheduler/process/thread model                                      │
│     - Memory/address spaces/allocators                                    │
│     - VFS + filesystem backends                                           │
│     - Networking stack                                                     │
│     - Window/compositor/GDI backing                                       │
│     - Security/capability policy                                          │
├────────────────────────────────────────────────────────────────────────────┤
│ L2: Driver framework + bus/domain drivers                                 │
│     - PCI, storage, USB, NIC, GPU, power                                 │
├────────────────────────────────────────────────────────────────────────────┤
│ L1: Arch/HW control plane                                                 │
│     - x86_64 traps/interrupts/timers/CPU bring-up                         │
└────────────────────────────────────────────────────────────────────────────┘
```

### Threading model (high level)

```text
[Per-CPU runqueue(s)] <-> [scheduler]
         |                    |
         |                    +--> task state transitions
         |                         (ready <-> running <-> blocked)
         |
         +--> timer ticks / yields drive preemption points
```

The scheduler is the shared execution substrate for native processes and PE-hosted Win32 workloads.

---

## 3) Syscall ABI contract (native kernel gateway)

All user-mode calls converge through `int 0x80` dispatch.

| Register | Meaning |
|---|---|
| `rax` | syscall number on entry; return value on exit |
| `rdi` | arg1 |
| `rsi` | arg2 |
| `rdx` | arg3 |
| `r10` | arg4 |
| `r8`  | arg5 |
| `r9`  | arg6 |

```text
user call site
  -> marshal args to (rdi,rsi,rdx,r10,r8,r9)
  -> rax = SYS_*
  -> int 0x80
  -> kernel dispatch table
  -> subsystem handler
  -> retval in rax
```

This stable gateway is what makes the Win32 translator layer thin and deterministic.

---

## 4) PE + Win32 execution path (how a Windows .exe actually runs)

### Import/launch flow

```text
PE bytes
  -> validation/reporting
  -> new process address space
  -> preload translator DLL set into process AS
  -> parse each DLL EAT
  -> map PE sections
  -> apply relocations
  -> walk imports
       -> resolve via preloaded DLL export tables
       -> patch IAT slots with resolved absolute VA
       -> recurse forwarders (bounded depth)
  -> create process/thread state + heap bootstrap
  -> schedule first user entry at PE EntryPoint
```

### Runtime call flow example (`send`)

```text
PE .text: call [__imp_send]
   -> ws2_32!send (translator DLL)
   -> Win32 calling convention -> SYS_SOCK_SEND marshal
   -> int 0x80
   -> kernel syscall dispatch
   -> net stack send path
   -> NIC driver TX ring programming
   -> packet on wire
```

The same kernel send backend is used by native sockets and Win32 sockets.

---

## 5) Subsystem matrix (current integration status)

| Domain | Backend owner | Status summary |
|---|---|---|
| File I/O (read path) | Kernel VFS + FAT32/ext4 + storage drivers | Working end-to-end |
| File I/O (write path) | Kernel backend incomplete | Translator returns controlled failures/stubs |
| Registry-like queries | User-side advapi32 tree | Working for current fixture coverage |
| Heap/thread primitives | Kernel process/thread + Win32 syscall surface | Working in live fixtures |
| Windowing/GDI basic path | Kernel window/compositor + GDI object plumbing | Working for basic paint/pump/tests |
| Network sync sockets | Kernel TCP/UDP/IP + NIC/USB transports | Working for sync path; async Winsock surface partial |
| 3D graphics API | Vulkan ICD not landed yet | D3D create paths are stubs/fail-fast |
| COM runtime surface | Not implemented | Returns documented failure paths |
| Audio | Minimal backend + select APIs | Partial |

---

## 6) Security and containment model (cross-cutting)

```text
Process launch
  -> CapSet attached (least privilege policy)
  -> Address space limits + region budgets
  -> W^X/NX map-time checks
  -> runtime syscall cap checks
  -> denial / logging / optional reap on abuse threshold
```

### Major active controls

- W^X enforcement on user mappings
- NX enabled
- SMEP/SMAP where available
- ASLR offsetting for image load
- Stack canary and retpoline hardening
- Capability-gated privileged syscalls
- Kernel-stack guard page strategy

Security policy is process-centric and capability-driven (not setuid-centric).

---

## 7) Filesystem + storage composition

```text
[VFS namespace]
    |
    +--> [ramfs/tmpfs]
    +--> [FAT32 reader]
    +--> [ext4 reader]
    +--> [NTFS/exFAT work-in-progress paths]

Block path:
VFS op -> fs backend -> block layer assumptions -> NVMe/AHCI driver -> hardware
```

This keeps user ABI stable while individual filesystem backends evolve.

---

## 8) Networking composition

```text
socket API (native or ws2_32 translator)
    -> syscall dispatch
    -> kernel net stack (ARP/IP/UDP/TCP + DNS/DHCP helpers)
    -> device adapter (e1000 / USB ECM / USB RNDIS)
    -> link
```

Current architecture already supports multiple link transports behind a shared socket-facing API.

---

## 9) Graphics/windowing composition

```text
user32/gdi32 translator calls
   -> SYS_WIN_* / SYS_GDI_*
   -> kernel window manager + compositor
   -> framebuffer/virtio-gpu scanout path
```

Near-term shape is 2D-first with explicit stubs for not-yet-landed 3D API paths.

---

## 10) Why this shape scales

```text
Single backend per domain
 + dual ABI front doors
 + stable syscall contract
 + capability-based security envelope
 = faster iteration without architecture fork risk
```

### Tradeoff summary

- **Pros**
  - No split-brain subsystem maintenance
  - Predictable behavior parity across native + Win32 callers
  - Easier observability and debugging at shared kernel choke points
- **Costs**
  - Translator correctness is critical (ABI marshalling must be exact)
  - Stub surfaces need disciplined, explicit failure behavior until backend lands
  - ABI stability constrains reckless syscall churn

---

## 11) Practical map: where to look in the tree

- `kernel/arch/x86_64/` → traps/interrupts/timers/CPU setup
- `kernel/mm/` → paging, frames, address-space, heap/stack primitives
- `kernel/sched/` → runqueues and scheduling core
- `kernel/fs/` → VFS + filesystem backends
- `kernel/net/` + `kernel/drivers/net/` → stack + adapters
- `kernel/subsystems/win32/` → Win32-facing syscall surfaces and state glue
- `kernel/subsystems/linux/` + `kernel/subsystems/translation/` → Linux ABI/translation surfaces
- `kernel/drivers/` → hardware domain drivers
- `userland/apps/` → native/PE fixture workloads used for live validation
- `docs/HISTORY.md` → historical landing order and milestone context

---

## 12) Build + smoke-test commands

```bash
# Configure
cmake --preset x86_64-debug

# Build
cmake --build build/x86_64-debug --parallel $(nproc)

# Runtime smoke (if runtime tooling is installed)
DUETOS_TIMEOUT=30 tools/qemu/run.sh build/x86_64-debug/duetos.iso
```

---

## 13) Non-negotiable architecture rules

1. One real backend per subsystem domain.
2. Win32 DLL layer is a translator, not an alternate kernel.
3. Syscall numbers are ABI commitments once published.
4. Security invariants (W^X/caps/etc.) are part of functional correctness.
5. If a subsystem exists, it must be wired into a real call path (or removed).

These constraints keep DuetOS coherent as it scales from bring-up to real workload execution.

## 14) CI topology and artifact channels

The repository keeps CI/release automation in-tree as the source of truth:

- [`.github/workflows/build.yml`](../.github/workflows/build.yml)
  - Format enforcement (`clang-format`)
  - Debug + release configure/build presets
  - Boot smoke (`tools/test/ctest-boot-smoke.sh`) in CI
- [`.github/workflows/release.yml`](../.github/workflows/release.yml)
  - Builds debug + release assets
  - Publishes rolling release tags to:
    - `latest-debug` (debug channel)
    - `latest-release` (release channel)
  - Triggers from `main`, `v*` tags, and manual dispatch

Artifact channels are intentionally split:

- **`latest-release`**: stable rolling channel from release preset artifacts.
- **`latest-debug`**: prerelease rolling channel from debug preset artifacts.

The Actions-tab run artifacts are short-retention diagnostics; GitHub Releases
under the two rolling tags are the long-lived distribution channels.

