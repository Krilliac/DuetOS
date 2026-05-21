# In-House Windows VMM (`duetos-vmm`)

> **Audience:** Kernel hackers / QA running or debugging DuetOS on Windows
>
> **Execution context:** Host tooling (Windows, native MSVC process) — outside the kernel entirely
>
> **Maturity:** v0 — slices 1-6 landed; written to spec, not yet boot-verified on Windows (see [Verification status](#verification-status))

## Overview

`duetos-vmm` is a bespoke Type-2 virtual machine monitor, tailored to
DuetOS, that boots the **unmodified** freestanding kernel ELF as a
hardware-virtualised guest on Windows via the **Windows Hypervisor
Platform** (WHP). It emulates only the firmware/devices DuetOS
actually probes and exposes host-side introspection plus a
GDB-remote that Visual Studio attaches to.

It lives at [`tools/vmm/`](../../tools/vmm/) as its **own MSVC CMake
project** — deliberately *not* `add_subdirectory()`'d from the
freestanding kernel build, and including **zero kernel headers**. It
treats the kernel as an opaque ELF plus a serial / ACPI / Multiboot2
contract. Being host tooling under `tools/`, kernel
[subsystem-isolation](../kernel/Subsystem-Isolation.md) rules do not
apply and nothing here can link into a kernel TU.

The kernel is untouched, so the QEMU / CI path (see
[QEMU Smoke](QEMU-Smoke.md)) is unaffected by anything in this tree.

## When to Use / When to Read

- You want to **run, test, or debug DuetOS on Windows** without QEMU.
- You want **source-level kernel debugging in Visual Studio** against
  the real guest (not a simulator).
- You want host-side **introspection** (symbolized RIP, named-global
  dumps, a vmexit trail) or **deterministic record/replay** of a
  session's host inputs.
- For booting DuetOS under QEMU/VMware/VirtualBox/bare-metal instead,
  see [Running on VMs](Running-on-VMs.md). For the in-kernel
  interactive debugger, see [Debugger](Debugger.md).

## Why a bespoke VMM (vs. QEMU + gdb)

The kernel runs **completely unmodified** — only the VMM is new, and
the VMM is the MSVC-native artefact. This preserves full fidelity
(real `boot.S` → long mode → paging → IRQ → PE-execution paths) while
giving a single Windows `.exe` you build and debug in Visual Studio,
*and* deep introspection that QEMU+gdb cannot offer because the VMM
owns guest physical memory, the page tables, and every vmexit.

This is **not** "port the kernel to a hosted target" — that would
test a simulated kernel. Here the genuine kernel boots on virtual
hardware.

## Architecture (slices)

| Slice | What it delivers |
|---|---|
| 1 | WHP partition + 1 vCPU; ELF loader (honours `p_paddr`/LMA); synthesised Multiboot2 (cmdline/meminfo/mmap/ACPI-new/end) + ACPI (RSDP→XSDT→{FADT,MADT,DSDT,FACS} — the kernel **panics** without an RSDP, so this is load-bearing; MADT advertises 1 LAPIC → clean single-vCPU boot); 16550 COM1 → boots to the serial banner |
| 2 | IOAPIC MMIO emulator (WHP has no MMIO emulator — a focused MOV decoder scoped to clang's `volatile u32*` codegen); PIT (channel-2 modelled against the real host clock so LAPIC calibration is correct; channel-0 fallback); COM1 RX + IRQ4; HLT-resume; opt-in idle watchdog |
| 3 | Host-side GDB remote: `target.xml` (amd64 core regs), `g/G`, `m/M` via `WHvTranslateGva`, `Z0/z0` software breakpoints, `c/s` with the breakpoint step-off dance; `launch.vs.json` attach config |
| 4 | ELF-symbol introspection + always-on 256-entry vmexit ring, via gdb `monitor` (`sym`/`lookup`/`read`/`rip`/`trace`); symbolized auto-dump on a fatal exit |
| 5 | Record / replay of host-origin inputs (serial RX, IOAPIC line raises, PIT-cal edge) keyed by vmexit sequence |
| 6 | `tools/vmm/vs-start-vmm.ps1` starter + documented `tasks.vs.json` snippet → one-F5 Visual Studio attach |
| 7 (Bridge B) | `vmm_dbg::` free functions reachable from VS's Immediate window: `ReadQ`/`WriteQ`/`Sym`/`Dump` resolve kernel symbol names to mapped host bytes via `ElfSymbols` + `GuestMemory`. `ElfSymbols::FindBySuffix` accepts unmangled queries (`"g_ticks"` → `_ZN6duetos4arch12_GLOBAL__N_17g_ticksE`). Volatile keepalive table defeats `/OPT:REF`. |
| 8 (Bridge A) | `Vmm::kernel` of type `GuestKernelView` — host pointers into mapped GPA, populated/refreshed on every guest exit. VS Watch sees `vmm.kernel.g_ticks` as a live, editable `uint64_t*`. Curated list extends trivially. |
| 9 (Bridge C) | Host-attach session can halt the guest at a guest symbol: `vmm_dbg::Claim()` flips the WHP exception-exit arbiter, `vmm_dbg::Bp("name")` plants `0xCC`, `HandleHostStop()` snapshots regs into `g_stop_state` and calls `__debugbreak()` (under `IsDebuggerPresent` guard); `vmm_dbg::Step()` / `Run()` resume. Coexists with the GDB stub (default off; Claim/Release transfers ownership). |
| 10 (Bridge D) | `tools/vmm/vmm.natvis` pretty-printers for `GuestKernelView`, `GuestStopState`, `ElfSymbols::Sym`. Embedded via CMake `target_sources` + `VS_TOOL_OVERRIDE "Natvis"`. |
| 11 | `--break` CLI flag: `__debugbreak()` in `main()` after arg-parse, gated by `IsDebuggerPresent()`, so VS native attach (F5) halts at a known stack frame before the vCPU runs. F5 default args include both `--break` and `--gdb 1234` so the two-window full-coverage debug flow Just Works. |

Source map (all under `tools/vmm/src/`): `whp.*` (partition/vCPU
RAII), `guest_memory.*`, `elf64.*`, `multiboot2.*`, `acpi.*`,
`mmio_emulator.*`, `devices/{serial16550,pit8254,ioapic,ps2_i8042}.*`,
`debug/{gdb_server,elf_symbols,exit_trace,introspect,record,
vmm_dbg,guest_view,host_stop}.*`, `vmm.*`, `main.cpp`. Visualisers in
`tools/vmm/vmm.natvis`.

For the full debugger workflow (how to use the GDB stub, the bridge,
or both at once), see [**VMM Debugging in Visual Studio**](VMM-Debugging.md).

## Build

Windows only (links `WinHvPlatform.lib`; needs the **Windows
Hypervisor Platform** optional feature enabled, virtualization on in
firmware, and — if the dev box is itself a VM — nested virt). On a
non-Windows host CMake fails fast by design.

```
cmake -S tools/vmm -B tools/vmm/build -G "Visual Studio 17 2022" -A x64
cmake --build tools/vmm/build --config Debug
```

The kernel ELF is produced by the **WSL clang preset build**
(`cmake --preset x86_64-debug && cmake --build build/x86_64-debug`) —
Visual Studio cannot build the freestanding kernel.

## Usage

```
duetos-vmm.exe --kernel <duetos-kernel.elf>
               [--mem <MiB>]            (default 512)
               [--cmdline "<...>"]      (default "console=ttyS0")
               [--idle <secs>]          (0 = no watchdog; default)
               [--gdb <port>]           (host-side GDB stub; 0 = off)
               [--record <f> | --replay <f>]
```

Guest COM1 streams to stdout; stdin is fed to COM1 RX. `--gdb` stops
the guest before the first instruction (like QEMU `-S`) so a client
can plant boot breakpoints.

`--idle` is **off by default** so an interactive shell parked at a
prompt is never killed; headless/CI runs pass a positive value to
bound a wedged boot.

### gdb `monitor` introspection

With `--gdb`, from the client: `monitor help`, `monitor sym
<hexaddr>`, `monitor lookup <name>`, `monitor read <name> [n]`,
`monitor rip`, `monitor trace`. A fatal/unexpected exit also
auto-dumps the symbolized vmexit ring to stdout even with no
debugger attached — the host analogue of the kernel boot-log trail.

### Record / replay

`--record <f>` captures serial RX, IOAPIC line raises, and the
PIT-ch2 calibration edge, keyed by the monotonic vmexit sequence.
`--replay <f>` feeds them back at the same exit-seq (stdin/timer
threads are suppressed; the kernel boots headless on a baked ramfs).

## Visual Studio one-F5 flow

Attach-style debugging needs the VMM running and parked on `accept()`
*before* VS connects, and the kernel ELF freshly built (WSL). The
committed starter [`tools/vmm/vs-start-vmm.ps1`](../../tools/vmm/vs-start-vmm.ps1)
does all of it (build kernel via WSL → build VMM → reap any orphan →
launch detached with `--gdb` → return once the port is accepting).

Wire it as a preLaunch task: copy the `tasks.vs.json` snippet
documented at the top of [`launch.vs.json`](../../launch.vs.json)
into the per-user (git-ignored) `.vs/tasks.vs.json`, add
`"preLaunchTask": "start-duetos-vmm"` to the **"DuetOS: Attach
(in-house VMM, tcp:1234)"** config, and F5. Without the task: run
`tools\vmm\vs-start-vmm.ps1 -BuildKernel` in PowerShell first, then
F5 that config.

**gdb locality (important):** the VMM is a native Windows process, so
its gdb port is on Windows `localhost`. Point the config's
`miDebuggerPath` at a **Windows/MSYS2 `gdb.exe`** — *not* the WSL
`/usr/bin/gdb`, because WSL2 cannot reach the Windows host via
`localhost`. (The QEMU configs in the same file legitimately use the
WSL gdb because QEMU + stub are WSL-side.)

## Determinism boundary

WHP's xApic emulation owns the LAPIC timer **internally** — its
firing is neither observable nor schedulable by the VMM. Therefore
record/replay is reproducible at **exit-sequence granularity**
(enough to re-hit a serial- or IRQ-ordering bug), **not**
cycle-exact. This is a fundamental WHP constraint, not a TODO.

## Verification status

Boot-verified on a Ryzen 7840HS Windows 11 host with WHP enabled.
`duetos-vmm.exe --kernel <elf> --mem 2048` reaches at least
`[security/module] self-test PASS` and runs the full boot-time
self-test battery (Result, string, hexdump, va-region, process,
fs/boot_slot, registry, vt, extable, fault-domain, diag/fault-react,
…). The MMIO MOV decoder (slice 2), PIT-ch2 calibration (slice 2),
and the GDB breakpoint step-off dance (slice 3) all clear that path.

Path-specific verification still TBD:
- Long-running guest stability beyond the self-test battery.
- Path A's source-level kernel stepping on this host configuration
  (Windows gdb against tcp:1234).
- Path B's `vmm_dbg::Claim()` + guest breakpoint flow under VS
  native attach (manual verification only; the smoke build covers
  default-off behaviour, the active path needs VS in-hand).

## Known GAPs

- **No DWARF type-aware pretty-printing for guest data via the bridge.**
  Layer A's `Vmm::kernel` exposes one curated primitive (`g_ticks`) and
  the natvis decorates POD types only. For source-level kernel struct
  inspection, use Path A (GDB stub) which DOES have full DWARF — see
  [VMM-Debugging.md](VMM-Debugging.md).
- **GDB stub:** no fully-async `^C` interrupt (stop via a breakpoint
  instead); no hardware watchpoints; guest-originated `int3` (kernel
  `KBP` probes) surface to the client while attached — run kernel
  probes disarmed under gdb, or use the bridge's `Claim()` to detour
  them into `HandleHostStop` instead.
- **Bilateral mirror drift guard deferred.** Slice 2's plan called
  for kernel-side `sizeof_report.h` + `static_assert` + a
  `KernelTaskMirror` POD in the VMM, both verifying layout against
  shared offset constants. v1 ships without it because no kernel
  struct is currently header-exposed with stable named fields — the
  scheduler `Task` is `.cpp`-only. Will land when the first
  non-primitive type genuinely needs a mirror.
- **No framebuffer / virtio-blk emulation** — intentionally **out of
  scope**, not deferred-broken: the kernel boots headless on a baked
  ramfs, so they are unneeded for the run/test/debug goal and would
  be unwired bloat. Revisit only if a GUI/disk workload needs them.
