# GDT + IDT v0 — Canonical Kernel Descriptors and Trap Path

**Last updated:** 2026-04-20
**Type:** Observation
**Status:** Active

## Description

Landed the canonical kernel GDT, the 256-entry IDT, exception stubs for all 32 architectural vectors, and a C++ dispatcher that dumps register state on fault. Verified end-to-end: `int3` in `kernel_main` → stub → dispatcher → full trap frame on COM1 → halt.

## Context

Applies to `kernel/arch/x86_64/{gdt,idt,traps,cpu,serial,exceptions.S}.*`. Supersedes the temporary GDT that still lives in `boot.S` for the 32→64-bit handoff — that stub GDT is loaded for the long-mode transition only, then immediately replaced by `GdtInit()`.

## Details

### GDT

5 slots weren't needed yet — v0 installs the minimal viable GDT:

| Slot | Selector | Descriptor | Purpose |
|------|----------|------------|---------|
| 0 | 0x00 | null | required by architecture |
| 1 | 0x08 | `0x00AF9A000000FFFF` | kernel code, DPL=0, long-mode |
| 2 | 0x10 | `0x00AF92000000FFFF` | kernel data, DPL=0 |

Not yet installed (deferred to when they're actually needed):
- User-mode code + data descriptors (DPL=3) — add when userland exists.
- TSS descriptor — add when IST stacks or privilege transitions are needed. Without a TSS, double-fault handling is on the shared kernel stack, which is fine until we have deep kernel-stack usage.

### GDT install sequence

`GdtInit()` does a `lgdt` followed by an explicit far-return trick to reload CS, then writes the data selector into DS/ES/FS/GS/SS. The far-return trick is necessary because `mov %cs, ...` is not a legal instruction — CS can only be reloaded via `jmp far`, `call far`, `ret far`, or `iret`. We use `lret` because it's the shortest path that doesn't need a memory operand.

### IDT

256 × 16-byte gates. `IdtInit()` wires vectors 0–31 to their stubs; vectors 32–255 are left as non-present gates. Any interrupt delivered to a non-present gate triggers #NP (vector 11), which we *do* have a handler for — so future misdelivered IRQs during bring-up at least produce a diagnostic instead of a silent triple-fault.

All gates are `0x8E = P | DPL=0 | type=0xE` (interrupt gate, clears IF on entry). Trap gates (type 0xF, preserves IF) aren't used yet; we'll move #DB and #BP to trap gates if/when we need reentrant debugging.

### Exception stubs — uniform trap frame

Every vector enters `isr_N`, which:
1. Pushes a fake `0` error code if the CPU didn't already push one (the quirky set: 8, 10, 11, 12, 13, 14, 17, 21, 29, 30 push one; the rest do not).
2. Pushes the vector number.
3. Jumps to `isr_common`, which pushes all 15 GPRs and calls `TrapDispatch(frame)`.

Stack layout seen by the dispatcher (low → high address):

```
r15, r14, r13, r12, r11, r10, r9, r8,
rbp, rdi, rsi, rdx, rcx, rbx, rax,
vector, error_code,
rip, cs, rflags, rsp, ss
```

The `TrapFrame` struct in `traps.h` matches this exactly. Do **not** reorder one without updating the other.

### Stack-alignment math for the `call`

`isr_common` pushes 15 GPRs + the stub pushed 2 words (vector, error_code) + CPU pushed 5 (rip, cs, rflags, rsp, ss) = 22 × 8 = 176 bytes. 176 mod 16 = 0. So RSP is already 16-byte aligned at the point of `call TrapDispatch` — no extra `sub rsp, 8` needed. Adding more pushes later will break this invariant; the commit-message comment flags the exact byte count so future edits notice.

### Self-test

`kernel_main` calls `RaiseSelfTestBreakpoint()` after IDT install, which executes `int3`. The dispatcher prints:

```
** CPU EXCEPTION **
  vector     : 0x0000000000000003
             (#BP Breakpoint)
  error_code : 0x0000000000000000
  rip        : 0x0000000000102915
  cs         : 0x0000000000000008   <- confirms GDT install
  rflags     : 0x0000000000000006
  rsp        : 0x000000000010bfc0
  ss         : 0x0000000000000010   <- confirms data selector reload
  --
  [all 15 GPRs]
[panic] Halting CPU.
```

`cs = 0x08` and `ss = 0x10` are the specific values that confirm both the GDT install and the data-segment reload worked. A kernel that reports `cs = 0x08` but the old segment descriptors is still possible if the far-return trick is edited wrong — reading `cs` alone isn't proof, but combined with a clean halt (no `CPU Reset` in qemu.log) it's solid enough.

### What is NOT in this commit

- No IRQ controller bring-up (PIC/APIC). Vectors 32+ are non-present; any hardware IRQ will #NP and panic.
- No IST stacks. Double-fault would use the same kernel stack, which could itself be the thing that's broken. Accept this until SMP lands.
- No syscall gate (vector 0x80 or SYSCALL MSRs). That's for the syscall-dispatch commit.
- No NMI chain. NMI vector 2 has a handler but we don't do anything special (no NMI watchdog, no reentrancy protection).
- No panic formatting beyond labelled hex. A real `printk` with `%s`/`%d` lands when we have slab allocator + logging backend.

### Rejected approach: `constinit` on descriptor pointers

Initial attempt was `constinit GdtPointer g_gdt_pointer = { ..., reinterpret_cast<u64>(&g_gdt[0]) };`. Clang rejects this: `reinterpret_cast` is not a constant expression per C++23, even when the address is link-time known. The fix is to not mark the pointer `constinit` and instead fill both fields at runtime inside `GdtInit()` / `IdtInit()`. Cost: one extra store at boot. Benefit: no surprise global-ctor emission, which is important because we don't run `.init_array`.

### How to verify after edits

```bash
cmake --build build/x86_64-debug
DUETOS_TIMEOUT=10 tools/qemu/run.sh
```

Expected output ends with the `** CPU EXCEPTION **` block above. If instead you see:
- **Repeated boot log** (GRUB menu reappears) → triple fault, likely during GdtInit (`lretq` with wrong CS) or IdtInit (broken gate). Check `qemu.log` — multiple `CPU Reset` records confirm the loop.
- **No "Trap path online" line** → either GdtInit or IdtInit hung. `tools/qemu/run.sh -s -S` + gdb to step through.
- **Different vector than 3** → the `isr_stub_table` indexing or the `SetGate` math is off. Cross-check the `.rodata` table in `exceptions.S` against `idt.cpp`.

## Notes

- The boot.S stub GDT lives because we need it to enter long mode *before* we can execute C++ code. Don't remove it — just don't extend it. All real GDT work belongs in `gdt.cpp`.
- The `RaiseSelfTestBreakpoint()` call in `kernel_main` is intentional today. Remove it once the next commit adds something meaningful to do after IDT install (physical frame allocator, probably).
- When a future commit adds hardware IRQs, prefer a single `arch::InterruptsInit()` entry point that calls `GdtInit` + `IdtInit` + whatever controller setup exists, rather than scattering init calls into `kernel_main`.
- **See also:** [kernel-bringup-v0.md](kernel-bringup-v0.md) for the boot.S stub GDT that precedes this; [iso-build-and-boot.md](iso-build-and-boot.md) for the QEMU verification flow.
