# W^X / NX Enforcement

> **Audience:** Kernel hackers, security folks
>
> **Execution context:** Kernel — checked at every page-map call
>
> **Maturity:** v0 stable

## Overview

DuetOS enforces **W^X (write XOR execute)** at the page-map choke
points. No mapping can be created with both `kPageWritable` and
without `kPageNoExecute`. This eliminates the canonical
shellcode-injection substrate by construction.

## Files

- `kernel/mm/paging.{h,cpp}` — kernel-half mappings (`mm::MapPage`)
- `kernel/mm/address_space.{h,cpp}` — user mappings
  (`AddressSpaceMapUserPage`)
- EFER.NXE is enabled in `PagingInit` so PTE bit 63
  (`kPageNoExecute`) is honoured by the CPU.

## Map-time Gate

Both `mm::MapPage` and `AddressSpaceMapUserPage` panic on
write+execute combinations. There is no flag that lets a caller
opt out — it is a structural rule, not a hint.

```cpp
if (Writable(flags) && !NoExecute(flags)) {
    PANIC("mm: W^X violation: writable mapping must be NX");
}
```

## Protect-time and aliasing gates

The map-time panic is necessary but not sufficient: a guest can reach
write+execute *without* a single W+X map by (a) creating two views of
the same frames — one writable, one executable (Win32 section aliasing)
— or (b) flipping a mapped page's protection from RW to RX afterwards
via `NtProtectVirtualMemory`. Both are now closed:

- **Section views** — `Section` tracks sticky `has_writable_view` /
  `has_executable_view` flags; `SectionMap`
  (`subsystems/win32/section.cpp`) refuses an executable view of a
  section that has (or had) a writable view, and vice-versa. (SEC-004,
  CWE-693.)
- **mprotect transitions** — `AddressSpaceProtectUserPage`
  (`mm/address_space.cpp`) refuses to add EXECUTE to a currently-writable
  user page (the W→X transition), keeping the invariant at protect time
  as well as map time. (SEC-004.)
- **ELF loader** — a `PT_LOAD` segment declaring both `PF_W` and `PF_X`
  is rejected as a load error *before* any page reaches the map-time
  gate, so a hostile image fails gracefully instead of tripping the
  panic (DoS). (SEC-006, CWE-272. The PE/DLL loaders already funnel
  through the map-time gate.)

## kPageGlobal Refused on User Pages

`kPageGlobal` (PTE bit 8) keeps a mapping in the TLB across CR3
flushes. On a kernel page that's a perf optimisation; on a **user**
page it would be a cross-process TLB leak — every process would see
the previous user's translation in the TLB until an `invlpg` cleared
it. `AddressSpaceMapUserPage` refuses `kPageGlobal` outright.

## Live Probes

`kernel/security/` runs adversarial probes during boot to verify W^X
holds:

- Allocate a frame.
- Try to map it `kPageWritable | kPageExecute` -- expect panic /
  refusal.
- Try a kernel-shellcode write into a `.text` page -- expect SMEP/SMAP
  trap.

See [Attack Simulation](Attack-Simulation.md).

## Related Defences

| Defence | Status | Where |
|---------|--------|-------|
| W^X | On, enforced at map | `mm::MapPage`, `AddressSpaceMapUserPage` |
| NX | On (EFER.NXE) | `PagingInit` |
| SMEP | On | CR4 setup |
| SMAP | On | CR4 setup; `stac/clac` around copy_to_user |
| KASLR | On | Kernel image randomisation at boot |
| ASLR | On (per-process) | `AddressSpace` image-load offset |
| Stack canary | On | Compiler-emitted; `__stack_chk_fail` panic |
| CFI / retpoline | On | Compiler flags |
| KPTI | Settled — not implemented | Every target CPU reports `RDCL_NO=1` in silicon; KPTI would be a 5–30% syscall cost mitigating an attack the hardware already prevents. Runtime probe (`arch::CpuMitigationsGet().needs_kpti`) is in tree; on a `RDCL_NO=0` boot the probe emits a loud serial WARN block. See [Roadmap](../reference/Roadmap.md#kpti-enable-settled--deferred). |

## Known Limits / GAPs

- **Kernel `.text` is mapped by boot 2 MiB PS pages with `P | RW`**
  today. That's a documented W^X gap on the kernel image itself,
  scheduled to fix when kernel `.text` moves to managed 4 KiB
  mappings (the gate that enables splitting PS pages without
  hurting boot direct-map performance).
- **KPTI** is settled-not-implemented (see table above). Not a W^X
  issue per se but listed for the layered-defence picture.

## Related Pages

- [Sandboxing](Sandboxing.md)
- [Memory Management](../kernel/Memory-Management.md)
- [Attack Simulation](Attack-Simulation.md)
- [Capabilities](Capabilities.md)
