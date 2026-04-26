# Debug tooling — in-OS symbol resolution + offline panic decode

**Last updated:** 2026-04-26
**Type:** Pattern
**Status:** Active

## Description

Triaging a kernel panic / crash dump used to mean exporting a serial
log to the host and running `objdump -d`, `addr2line`, and `nm` against
the kernel ELF. Most of what those tools provide is now baked into the
running OS, so debugging a live system never needs to leave it. The
host-side scripts stay in `tools/` for the offline / saved-log
workflow.

## In-OS coverage

| Need | Live OS command / panic line |
|------|-------------------------------|
| Resolve a kernel VA → fn+offset (file:line) | `addr2sym <hex-addr>` (shell), or every panic line is auto-annotated `[fn+0xOFF (file:line)]` via the embedded symbol table (`kernel/core/symbols.h`) |
| 16-byte instruction dump at an address | `instr <hex-addr> [len]` (shell), or `[fault-rip] instr@<addr> : <16 bytes>` in every crash dump |
| Function inventory (~`nm`) | The embedded symbol table is the same source — every name shows up in panic backtraces and the `addr2sym` reverse lookup |
| Walk a backtrace from RIP/RBP | `dumpstate` / panic-time backtrace (already prints `#N rip=<sym> rbp=<addr>`) |
| Opcode classifier (~`objdump --disassemble-classes`) | `inspect opcodes <path>` |
| Find syscall idioms inside a binary | `inspect syscalls <path>` |

The symbol table is generated at build time by
`tools/gen-symbols.sh` (sorted by address, ~3K entries) and linked
into the kernel as `.rodata`. The resolver is allocation-free, lock-
free, and panic-safe — it's used from inside the trap dispatcher
itself.

What the kernel does NOT do, and offline tools still beat it at:

- **Decoded x86_64 assembly mnemonics**. The kernel only prints the
  raw bytes for a fault RIP (`5D C3 CC CC ...`); turning those into
  `pop %rbp; ret; int3; ...` requires a real disassembler and that's
  a pile of code we don't carry in-kernel. The host scripts use
  `objdump` / `llvm-objdump` for that.
- **Cross-binary RIP lookup**. Tasks loaded from /bin/* PE images
  have RIPs in user space; the kernel symbol table only covers
  kernel VAs. Host-side `tools/symbolize.sh` falls back to the PE
  loader's own debug info if available.

## Host scripts (offline reuse)

### `tools/symbolize.sh` (pre-existing)

```
tools/symbolize.sh [KERNEL_ELF] < panic_log.txt
tools/qemu/run.sh 2>&1 | tools/symbolize.sh
```

Annotate every kernel-VA hex in a serial log with
`[name+0xOFF (file:line)]`. Uses `llvm-symbolizer` if available, falls
back to `addr2line` (binutils).

### `tools/disasm-at.sh` (new, this slice)

```
tools/disasm-at.sh <hex-addr> [bytes-before] [bytes-after] [kernel-elf]
```

A focused `objdump -d` window. Prints disassembly between
`addr - bytes-before` and `addr + bytes-after`. Defaults: 16 / 32 /
`build/x86_64-debug/kernel/duetos-kernel.elf`. The same hex-bytes
view is available live via the in-OS `instr` command, but `disasm-at`
also decodes the bytes into mnemonics.

### `tools/decode-panic.sh` (new, this slice)

```
tools/decode-panic.sh [serial-log] [kernel-elf]
tools/qemu/run.sh 2>&1 | tools/decode-panic.sh - [kernel-elf]
```

Composes `symbolize.sh` + `disasm-at.sh` end-to-end:

1. Extracts every `=== DUETOS CRASH DUMP BEGIN ===` … `END ===`
   block from the log (handles multiple blocks if the panic path
   itself faulted).
2. Runs the bracketed record through `symbolize.sh` so every hex
   gets annotated.
3. For every distinct `rip:` line in the records, runs
   `disasm-at.sh` with a 16/32 window so the actual instruction
   stream around the fault is readable.

This is the canonical host-side workflow for "I have a serial log
but the system that produced it is gone" triage.

## Worked example — the boot-stack #DF reproducer

Stress-induced flake on `tools/qemu/run.sh`:

```
=== DUETOS CRASH DUMP BEGIN ===
  message  : #DF Double fault
  rip       : 0xffffffff801c1ce8 [region=k.text]
  ...
```

Live in the OS:

```
> addr2sym 0xffffffff801c1ce8
ADDR2SYM 0xffffffff801c1ce8 -> duetos::arch::WriteCr3+0x18
> instr 0xffffffff801c1ce8 16
[instr] instr@0xffffffff801c1ce8 : 5D C3 CC CC CC CC CC CC F3 0F 1E FA 55 48 89 E5
```

Offline (saved log + ELF):

```
$ tools/decode-panic.sh build/x86_64-debug/ctest-smoke-serial.log
... [extracted record with annotations] ...
--- rip 0xffffffff801c1ce8 ---
ffffffff801c1ce4: 48 83 c4 08            add    $0x8,%rsp
ffffffff801c1ce8: 5d                     pop    %rbp        ← fault here
ffffffff801c1ce9: c3                     ret
```

Both paths converge on the same answer (`pop %rbp` after `mov %cr3`,
inside `WriteCr3`), and from there the boot-stack high-VMA fix
follows directly. See `boot-stack-high-vma-fix.md`.
