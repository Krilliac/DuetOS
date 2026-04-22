# Kernel breakpoint subsystem v0 (phase 1)

**Last updated:** 2026-04-22
**Type:** Observation
**Status:** Active — SW + HW breakpoints land, `bp` shell command
wired, self-test runs at boot. Phases 2 (per-task syscall API) and
3 (static probe macros) planned but not implemented.

## Files

- `kernel/debug/dr.h` — header-only `ReadDrN` / `WriteDrN` inlines
  plus DR6/DR7 bit constants. Follows the MSR-helper idiom from
  `lapic.cpp`.
- `kernel/debug/breakpoints.{h,cpp}` — manager. 16 software slots,
  4 hardware slots (one per DR0..DR3). Internal `SpinLock` guards
  the tables.
- `kernel/arch/x86_64/traps.cpp:320–330` — trap-dispatch hook.
  `#BP` (vec 3) and `#DB` (vec 1) route through the manager
  before the generic `LogAndContinue` log line; the manager's
  return value decides whether the fallback fires.
- `kernel/core/shell.cpp:~2360 / ~6246` — `CmdBp` + dispatch
  entry for `bp` / `breakpoint`.
- `kernel/core/main.cpp:~298` — `BpInit()` + `BpSelfTest()`
  called after `ProtectKernelImage()` and before SMP bring-up.
- `kernel/mm/paging.h / paging.cpp:780` — `SetPteFlags4K`
  promoted from the anonymous namespace to public API so the
  BP subsystem can flip `.text` writable for int3 patching.

## How SW breakpoints work

1. Install: flip the containing 4 KiB page to RW via
   `SetPteFlags4K(page, kPagePresent | kPageWritable)`, save
   the original byte, write `0xCC`, flip the page back to R+X.
2. On `#BP` (vector 3): the CPU pushed rip pointing past the
   `0xCC`. Look up `rip-1`, rewind the frame's rip, restore the
   original byte, OR `RFLAGS.TF` into the frame, record a
   pending-reinsert entry. Return true → iretq resumes at the
   patched address, executes one instruction, takes `#DB`.
3. On `#DB` with `DR6.BS` set + pending reinsert: re-patch the
   `0xCC`, clear pending, clear `RFLAGS.TF` in the frame
   (the CPU does NOT auto-clear TF in the saved image — only in
   the live RFLAGS during the handler), clear `DR6`, return.

The TF-preservation-in-saved-image quirk is the single easiest
mistake to make here. Symptom if you forget: every subsequent
instruction fires another `#DB` forever.

## How HW breakpoints work

1. Install: pick a free DR0..DR3 slot, write the address, OR
   the slot's (R/W, LEN, L-enable, MBS) bits into DR7.
2. On `#DB`: read DR6, scan B0..B3 for which slot fired, log
   the hit, increment per-slot counter, clear DR6.
3. For execute BPs we also OR `RFLAGS.RF` (0x10000) into the
   frame — the Intel SDM says the CPU sets RF automatically on
   instruction-BP delivery so iretq can resume without
   re-triggering the same fetch, but QEMU's TCG doesn't
   propagate that bit reliably. Setting it explicitly is
   defensive; it's a no-op on real hardware where the CPU
   already did it.

## Shell command

```
BP LIST                              — list installed breakpoints
BP SET <hex-addr>                    — software BP at kernel .text address
BP HW <hex-addr> [X|W|RW] [LEN]      — hardware BP (execute/write/read-write)
BP CLEAR <id>                        — remove by id
BP TEST                              — round-trip self-test
```

Output formats for `bp list`:

```
BP: ID KIND   ADDR              HITS
   1  SW     0xffffffff801445a0  0
   2  HW-W   0xffffffff80200000  17
```

## Phase 1 scope cuts

- **Single-CPU only.** Install routines reject `SmpCpusOnline()
  != 1` with `SmpUnsupported`. When SMP scheduler support lands,
  DR writes need IPI-broadcast to all CPUs and SW patches need
  either a quiesce-then-patch primitive or per-CPU per-core
  invalidation. See `kernel/arch/x86_64/smp.h:8–29`.
- **Kernel `.text` only for SW BPs.** Process-image patching +
  per-task DR save/restore on context switch = phase 2.
- **No ring-3 syscall.** User code has no way to install a BP
  yet; the `bp` shell command is keyboard-only and runs in
  ring 0 directly. Capability gating (`kCapDebug`?) lands with
  the syscall in phase 2.
- **One-shot reinsertion.** If a second SW BP hit arrives while
  a reinsert is pending (which shouldn't happen in phase 1's
  single-CPU no-reentrancy world), we log + drop. A proper
  per-CPU pending queue is needed before nested debugging.
- **No probe macros.** Phase 3 will add a `KBP_PROBE(reason)`
  macro sprinkled at panic paths, sandbox denials, scheduler
  edge cases, etc. — lets an operator pre-arm the subsystem
  to trap only on specific events.

## Gotchas discovered during bring-up

1. **`BpInfo infos[N]{}` compiles to a `memset` call.** The
   kernel has no memset symbol in this TU; the linker fails.
   Fix: declare without the `{}` initialiser; `BpList` only
   populates valid entries so pre-zero isn't needed.
2. **`SetPteFlags4K` was in an anonymous namespace**, preventing
   external linkage. Moved it out (new file-scope definition in
   paging.cpp after the anon-ns close brace, header prototype
   in paging.h).
3. **RF handling on TCG.** Real CPUs auto-set RF on the pushed
   rflags for instruction-BP delivery; TCG apparently doesn't.
   Always OR RF into `frame->rflags` before returning for HW
   execute BPs.
4. **TF is NOT auto-cleared in the saved rflags image** — only
   in the live register while the handler runs. If your `#DB`
   handler forgets to clear it, the caller single-steps forever.

## Self-test at boot

`main.cpp:~298` runs `BpInit()` then `BpSelfTest()` which:

1. Installs a SW BP at the internal `BpSelfTestTarget` function,
   calls it, verifies `hit_count == 1`, removes it.
2. Same round trip with a HW execute BP.

A failure logs a warning and boot continues — we don't want a
subtle debug-subsystem regression to brick the box on every
boot. Health scans still report 0 issues if the test failed
(the BP subsystem doesn't register a health probe yet; phase 2
wiring).
