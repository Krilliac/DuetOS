# Detour / memory-hooking hardening — v0

**Type:** Decision + Observation
**Status:** Active
**Last updated:** 2026-04-20
**Branch:** `claude/add-process-sandboxing-e0pnT`

Summary of how CustomOS defends against the family of attacks that
Windows malware / rootkits have historically used: inline hooks,
IAT/PLT detours, vtable hijacking, SSDT hooking, and ROP. Every
defensive layer below is implemented and live-boot-verified.

## The attacker's goal

"Detour" = cause YOUR code to start executing MY code without
modifying it statically. Common mechanisms:

1. **Inline hook**: write a 5-byte `jmp rel32` over the first
   instructions of a target function. Next call to that function
   lands in attacker code.
2. **IAT/PLT patch**: overwrite a function-pointer entry in the
   import table so calls through that pointer go somewhere else.
3. **Vtable hijack**: overwrite a C++ object's vtable with a
   pointer to an attacker-controlled table.
4. **Return-address smash**: overflow a stack buffer, overwrite
   saved return address, ret into a gadget chain.
5. **SSDT / IDT hook**: overwrite a kernel dispatch table so
   syscall/interrupt delivery lands at attacker code.

## Defenses in CustomOS (all live as of this branch)

### Write-side (can the attacker modify code?)

- **User code page is R+X** (no W). `AddressSpaceMapUserPage`
  refuses to create a W+X mapping at all (slice 6). `MapPage`
  enforces the same rule for kernel-half mappings.
- **Kernel `.text` is R+X**. `ProtectKernelImage` splits the
  2 MiB PS direct map and installs per-section PTE flags
  (slice 10b).
- **CR0.WP = 1**. Even ring 0 cannot write to a RO page
  (slice 17). Protects against a kernel bug with a bad
  pointer inadvertently scribbling `.text`.
- **Per-process AS**. Process A cannot map or modify process
  B's pages at all — the PML4s are disjoint on the user half
  (slice 1).
- **Capability-gated syscalls**. There's no syscall that
  grants "write to arbitrary memory" — no `SYS_WRITEMEM`,
  no `ptrace`, no `process_vm_writev`. Slice 2.

### Execute-side (can the attacker jump to their injected code?)

- **NX on all writable pages**. User stack + heap pages and
  kernel `.data` / `.bss` are `kPageNoExecute` (slice 6 + 10b).
  Instruction fetch from them raises `#PF` with err bit 4
  (I/D). Live-proven by `ring3-nx-probe`.
- **CFI via CET / IBT**. Every indirect branch must target an
  `endbr64` instruction; otherwise `#CP`. 264+ endbr instances
  in the final ELF. Compiler and hand-written asm both
  emit them (slice 13).
- **Retpoline**. `-mretpoline` replaces indirect branches with
  a thunk that traps speculation at `lfence`. Attackers can't
  use mispredicted indirect branches to speculate into a gadget
  (slice 19). Complementary to IBT: retpoline prevents the
  branch from being steered; IBT prevents a steered branch
  from landing.
- **Stack canaries**. Every kernel function with a buffer or
  address-of-local has a prologue/epilogue pair that catches
  return-address corruption. `-fstack-protector-strong`;
  `__stack_chk_fail` panics (slice 12).
- **ASLR**. User code / stack base VAs randomised per process
  (slice 11). Attacker can't precompute gadget or target
  addresses.

### Info-leak side (can the attacker find gadgets / pointers?)

- **Per-process AS** means ring 3 can't read any kernel VA
  directly (kernel-half PTEs have no User bit).
- **SMAP** means ring 0 can't accidentally dereference a user
  pointer without explicit `stac` (enforced by every
  `CopyFromUser` / `CopyToUser` call path).
- **SMEP** means ring 0 can't accidentally execute a user
  page. Defeats "map shellcode in ring 3, pivot via a bug to
  exec it from ring 0".
- **User frames zero-on-alloc** (slice 18). A freshly-mapped
  user page never contains stale kernel data — no info-leak
  via "allocate page, read it".
- **Heap free-poison** (pre-existing). Freed kheap blocks get
  filled with `kHeapFreePoison` so UAF reads surface as
  recognisable garbage in a panic backtrace rather than
  usable stale pointers.

### Detect-side (if an attempt fires, do we notice?)

- **Ring-3 exception → `[task-kill]`**. A fault from ring 3
  (including jail-probe, nx-probe, random smashes) produces
  a single-line log with pid / rip / cr2 / err and terminates
  the offending task without halting the kernel (slice 8).
- **Sandbox-denial counter**. A process that retries blocked
  syscalls is killed at 100 denials: `[sandbox] pid=N hit
  100 denials — terminating as malicious` (slice 16).
- **CPU-tick budget**. A process that burns beyond its budget
  is killed: `[sched] tick budget exhausted pid=N` (slice 14).
- **`__copy_user_fault_fixup`**. Even a kernel #PF inside the
  user-copy byte loop recovers gracefully — the caller sees
  `false`, logs `[extable] recovered kernel #PF in user-copy
  helper` (slice 15).
- **Kernel W^X violation**. If ring 0 ever tries to write a
  RO page (kernel bug), CR0.WP converts it into a #PF at
  that exact instruction. Slice 17.

## Threat-model coverage table

| Attack | Defense |
|---|---|
| Overwrite own code (inline hook of self) | W^X (user code is R+X) |
| Overwrite another process's code | Per-process AS |
| Overwrite kernel `.text` (from ring 0) | Kernel `.text` RO + CR0.WP |
| Exec from stack/heap | NX everywhere writable |
| Exec from RW page after unmap-remap trick | No `mprotect`-equivalent syscall; W^X at map |
| Stack buffer overflow → return-addr smash | Stack canaries + `-fstack-protector-strong` |
| ROP / return-into-gadget | ASLR + CFI/IBT |
| Branch-target injection (Spectre-v2) | Retpoline |
| Leak stale kernel data through a fresh page | Zero-on-alloc |
| Guess pointers from a UAF | Heap free-poison |
| Brute-force blocked syscalls | 100-denial auto-kill |
| User fault → DoS kernel | Ring-3 `[task-kill]` |
| Kernel `#PF` from bad user pointer | `__copy_user_fault_fixup` |
| Steal kernel memory via direct read | SMAP + per-process AS |
| Steal kernel memory via direct exec | SMEP |

## What's still deliberately out of scope

- **Meltdown / Spectre-v1 mitigations beyond retpoline**. KPTI,
  SLH (`-mspeculative-load-hardening`), STIBP/IBRS are future
  slices. Without them, a malicious process on a vulnerable CPU
  could still speculatively read kernel memory despite SMAP
  (Meltdown) or across the branch predictor (Spectre-v1).
- **CET Shadow Stacks (SHSTK)**. We have IBT but not SHSTK —
  ROP via return-address forgery is still theoretically
  possible if stack canaries miss a specific overflow pattern.
- **Code signing / PE-image validation**. When the PE loader
  lands, only signed binaries should execute in a trusted
  profile.
- **IOMMU / DMA containment**. We have no PCIe device drivers
  yet that initiate DMA; when they arrive, an IOMMU config
  prevents devices from reading / writing arbitrary physical
  memory (important for malicious peripherals).
- **KASLR**. Kernel image is linked at a fixed high-half VA
  (0xFFFFFFFF80000000); a local attacker who can leak ANY
  kernel pointer reveals the whole map. ASLR randomises user;
  KASLR (future) randomises kernel.

## Commit map

| SHA | Slice | Role |
|---|---|---|
| 7b9d816 | 1   | Per-process AS   (write-side: others can't touch you) |
| ccce588 | 2   | Cap-gated syscalls (write-side: no ambient authority) |
| 00206e4 | 6   | W^X enforcement at map (write-side: no W+X pages) |
| 688ea51 | 10b | Kernel `.text` RO  (write-side: kernel code immutable) |
| c21d7a0 | 12  | Stack canaries     (detect-side: return-addr smash) |
| 6af0a4a | 13  | CET/IBT            (exec-side: landing-pad required) |
| af38372 | 8   | Ring-3 task-kill   (detect-side: faults don't DoS) |
| fcc92c2 | 11  | ASLR               (exec-side: gadget addrs unknown) |
| b629cb9 | 15  | Copy fault-fixup   (detect-side: kernel #PF recovers) |
| c779a6b | 16  | Denial threshold   (detect-side: brute-force kill) |
| 7586e10 | 17-19 | CR0.WP + zero-alloc + retpoline (THIS commit set) |
