# Kernel Bring-Up v0 — Multiboot2 → Long Mode → `kernel_main`

**Last updated:** 2026-04-20
**Type:** Observation
**Status:** Active

## Description

The very first boot path landed in the tree. Documented here so future sessions don't have to re-derive the handoff state, the temporary GDT layout, or why certain flags are set in the toolchain file.

## Context

Applies to `kernel/arch/x86_64/boot.S`, `kernel/arch/x86_64/linker.ld`, `kernel/core/main.cpp`, and the freestanding toolchain in `cmake/toolchains/x86_64-kernel.cmake`. This is the first buildable kernel image in the project; the bring-up commit is on `main` (search log for "kernel bring-up v0").

## Details

### Boot protocol

- **Multiboot2** (spec magic `0xE85250D6`, architecture = i386). Header lives in a dedicated `.multiboot2` section that the linker script forces to the top of the image, within the first 32 KiB and 8-byte aligned.
- Handoff: loader jumps to `_start` in 32-bit protected mode with `eax = 0x36D76289` (Multiboot2 boot magic) and `ebx` pointing at the info struct.
- We stash both registers into `edi`/`esi` before clobbering anything, so by the time we call `kernel_main` they're already in the SysV AMD64 argument positions (`rdi`, `rsi`).

### Long-mode bring-up

Minimal viable: identity-map the first 2 MiB using one 2 MiB PDE. Three tables, each 4 KiB, live in `.bss`:

```
boot_pml4[0]  -> boot_pdpt  (P|RW)
boot_pdpt[0]  -> boot_pd    (P|RW)
boot_pd[0]    -> phys 0     (P|RW|PS)   ; 2 MiB huge page
```

Then: `cr3 = pml4`, `cr4.PAE = 1`, `EFER.LME = 1`, `cr0.PG = 1`, `lgdt`, `ljmp 0x08:long_mode_entry`. No TLB-shootdown or SMP bring-up yet.

### Temporary GDT

Three entries, lives in `.rodata`:
- `0x00` — null
- `0x08` — 64-bit code (`0x00AF9A000000FFFF`)
- `0x10` — 64-bit data (`0x00AF92000000FFFF`)

This GDT is **temporary**. The real kernel GDT (with TSS, per-CPU GSBASE, and userland segments) is a future subsystem.

### What is NOT in this commit

- No IDT. Any exception → triple fault → QEMU reset.
- No higher-half mapping. Kernel runs at physical = virtual.
- No paging allocator. The three boot tables are static in `.bss`.
- No SMP. AP bring-up is future work.
- No interrupts. COM1 output is polling-only.
- No panic handler beyond a `cli; hlt; jmp $-1` loop.

Each of these is a separate, well-scoped follow-up commit. Do not smear them into `boot.S` — keep `boot.S` minimal and push complexity into proper C++ modules.

### Toolchain flags that matter and why

| Flag | Reason |
|------|--------|
| `--target=x86_64-unknown-none-elf` | Pure ELF, no OS ABI. No host headers. |
| `-ffreestanding` | No hosted libc assumption. |
| `-fno-stack-protector` | No `__stack_chk_*` symbols to satisfy. |
| `-mno-red-zone` | Interrupts must not corrupt below-RSP; red zone is illegal in kernel. |
| `-mno-sse`, `-mno-mmx`, `-mno-80387`, `-mgeneral-regs-only` | No implicit vector codegen. FPU/SSE save is per-thread, managed by scheduler. |
| `-mcmodel=kernel` | Addressing for kernel (high-half compatible once we move there). |
| `-fno-pic`, `-fno-pie` | Fixed-address kernel load; no GOT/PLT indirection. |
| `-fno-exceptions`, `-fno-rtti`, `-fno-threadsafe-statics` | No C++ runtime dependency. |
| `-Wl,--build-id=none` | Don't emit build-id note; we don't use it. |
| `-Wl,-z,noexecstack` | Silences lld's PT_GNU_STACK warning. |

### How to verify after edits

```bash
cmake --preset x86_64-debug
cmake --build build/x86_64-debug --parallel $(nproc)

# Check Multiboot2 header (expect d6 52 50 e8 at offset 0x100000):
llvm-objdump -s --section=.multiboot2 build/x86_64-debug/kernel/duetos-kernel.elf

# Entry must be at 0x101000 (start of .text.boot):
llvm-readelf -h build/x86_64-debug/kernel/duetos-kernel.elf | grep Entry

# When qemu-system-x86_64 is installed:
tools/qemu/run.sh
# Expected serial output:
#   [boot] DuetOS kernel reached long mode.
#   [boot] Multiboot2 handoff verified.
#   [boot] Halting CPU.
```

### Notes / caveats

- `llvm-objdump -d` on `.text.boot` decodes as 64-bit (showing `movabsl` on what is actually a 32-bit `mov [abs], eax`). This is a cosmetic disassembler limitation, **not** a code issue. Use `ndisasm -b 32` or `objdump -M i386` against the extracted section bytes if you need a clean 32-bit view.
- QEMU's `-kernel` flag uses **Multiboot 1**, not 2. This works today only because `run.sh` is a placeholder; real booting requires `grub-mkrescue`-built ISO (and `qemu-system-x86` / `grub-pc-bin` / `xorriso` installed). The ISO build helper is the next natural commit.
- The stack is 16 KiB in `.bss`. Size it up when the kernel gets real work to do; 16 KiB is enough for `kernel_main` + serial init and nothing else.

## See also

- [win32-subsystem-design.md](win32-subsystem-design.md) — what this bring-up is the foundation for.
- [hardware-target-matrix.md](hardware-target-matrix.md) — the CPU features this boot path can assume (long mode, PAE).
- `CLAUDE.md` → "Boot path (x86_64)".
