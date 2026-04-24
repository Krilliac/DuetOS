# DEP / NX / W^X — v0

**Type:** Observation
**Status:** Active
**Last updated:** 2026-04-20

"DEP" is what Windows calls the feature; the CPU calls it NX (No-Execute,
AMD naming) or XD (Intel naming, same bit). It is the per-PTE flag at
bit 63 that forbids instruction fetch from the page. Combined with
enforcing "no page is ever both Writable and Executable" (W^X), you
get: a writable page cannot be executed, and an executable page cannot
be written. That's the whole game.

## Enforcement layers on DuetOS

### CPU-level enable

`PagingInit` sets `EFER.NXE` (MSR `0xC0000080` bit 11). Without this
bit, the CPU ignores bit 63 of every PTE — `kPageNoExecute` becomes
a no-op. EFER.NXE is on EVERY x86_64 CPU we'll ever target.

### Mapping-time gate (slice 6)

`mm::MapPage` and `mm::AddressSpaceMapUserPage` panic if the flags
include `kPageWritable` without `kPageNoExecute`. No code path in the
kernel can CREATE a W+X page. `kPageGlobal` is also refused on user
pages (cross-process TLB leak risk).

### User-mode mappings (slice 1 + 6)

`ring3_smoke` maps every user task with:
- code page: `kPagePresent | kPageUser` → R + X (no W, no NX)
- stack page: `kPagePresent | kPageWritable | kPageUser | kPageNoExecute` → R + W (NX)

### Kernel-mode mappings (slice 10b)

`ProtectKernelImage` (called at boot after `PagingInit`) splits the
2 MiB PS direct map covering the kernel image into 4 KiB pages, then
applies per-section flags:

| Section    | PTE flags                              | Effective access |
|------------|----------------------------------------|------------------|
| `.text`    | `Present`                              | R + X            |
| `.rodata`  | `Present + NX`                         | R                |
| `.data`    | `Present + Writable + NX`              | R + W            |
| `.bss`     | `Present + Writable + NX`              | R + W            |

Before this runs, every kernel byte was R + W + X by default
(boot.S's 2 MiB PS pages carried W=1 and NX=0). A stray write
through a kernel pointer into `.text` would have silently corrupted
code. Now it #PFs at the write site.

### PS-page split mechanics

Splitting a 2 MiB PS entry into 512 4 KiB PTEs has two subtleties:

1. **Preserve physical base and inheritable leaf flags.** The new PT
   mirrors the PS mapping byte-for-byte — same phys base, same W/NX
   bits on each leaf (which `SetPteFlags4K` then overwrites for the
   specific section's pages).
2. **PD pointer must be PERMISSIVE.** The CPU AND-combines W and
   OR-combines NX through the walk. If the PD pointer has W=0, no
   leaf can be written regardless of its own W bit. If PD has NX=1,
   no leaf can be executed regardless of its own NX bit. So the PD
   pointer for a mixed-content region (`.text` + `.data` under the
   same 2 MiB PS) must have W=1 and NX=0 — the per-leaf flags
   decide the real protection.

Every 4 KiB VA the split covers gets `invlpg`'d so the CPU can't
continue using the cached 2 MiB TLB entry.

### Verification

Two live-boot tests prove NX is actually enforced:

- **`ring3-jail-probe`** — writes to its RX code page.
  Fault: `#PF err=0x7` (Present + Write + User). W^X WRITE arm.
- **`ring3-nx-probe`** — jumps into its NX stack page.
  Fault: `#PF err=0x15` (Present + User + **I/D** (bit 4)).
  W^X EXECUTE arm. Bit 4 set is the CPU's explicit "NX stopped
  this fetch" signal.

Both end with `[task-kill] ring-3 task took #PF Page fault` (slice 8)
— the kernel terminates the offending task and keeps running.

### What DEP / NX does NOT cover

- **Race conditions on W^X.** If a single PTE could briefly be
  remapped W+X and back, an attacker could win the race. Our
  `MapPage` / `MapUserPage` reject W+X at creation time, there's
  no `mprotect`-equivalent yet, and every PTE edit is surrounded
  by `invlpg`. Revisit if an `mprotect` syscall lands.
- **ROP.** NX stops execution from data pages but not from the
  existing `.text`. Defence in depth there is CFI (Control-Flow
  Integrity) + stack canaries + shadow stacks, all future work.
- **JIT / dynamic code.** A future JIT (e.g. Vulkan shader
  compiler) would need a dedicated mapping path: allocate a page,
  map R+W, write code, remap R+X. Two distinct operations; never
  one page with both.
- **Kernel's `.text.boot` / `.bss.boot`.** Still R+W+X via the
  low-half identity map — bring-up-only code, unreachable after
  `kernel_main` jumps to the high half, but technically not
  protected. Easy follow-up is to unmap the identity map entirely
  once we've confirmed nothing in the kernel addresses it.

### Commit map

| SHA (approx) | Slice | What |
|---|---|---|
| 00206e4 | 6 | `MapPage` / `MapUserPage` refuse W+X at create |
| 10004b0 | 10a | `ring3-nx-probe` — CPU-level NX proof in user mode |
| 688ea51 | 10b | Kernel-image W^X via PS-split + per-section PTE flags |
