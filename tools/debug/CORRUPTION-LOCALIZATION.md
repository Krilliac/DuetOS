# Localizing memory corruption / UAF / random-RIP #PF in DuetOS

For kernel #PF / #UD / triple-faults whose RIP doesn't point at obviously-
buggy code; for slab integrity-check failures; for "kernel reads garbage
from a struct we just initialised"; for KASAN/UBSAN-style red-zone hits.

This is the class CLAUDE.md memory `sched-stack-align-fix.md` documents
(8B SysV-phase misalignment found via tray-click UBSan flood) — same
methodology shape.

---

## PROMPT (paste verbatim)

```text
DuetOS is hitting memory corruption — a kernel #PF/#UD at a RIP whose
source doesn't obviously match the fault, OR a slab integrity check
fired, OR a value we just wrote reads back as garbage. Localize using
the corruption-bisect methodology in tools/debug/CORRUPTION-LOCALIZATION.md.

SYMPTOM:
  <paste the panic banner: vector, CR2, RIP, the 16-frame backtrace, AND
   the 16-quadword stack dump. CLAUDE.md core/panic emits all of these —
   include EVERYTHING the dump emitted, even if it looks redundant.>

==========================================================================
STEP 1 — Resolve the RIP to a source line.

  RIP_HEX=<paste the value, e.g. 0xffffffff80460386>
  cd ~/source/DuetOS
  ELF=build/x86_64-debug/kernel/duetos-kernel.elf  # debug for symbols
  /usr/lib/llvm-18/bin/llvm-addr2line -e $ELF -fpi $RIP_HEX
  # Also: where the faulting instruction is in its enclosing function
  /usr/lib/llvm-18/bin/llvm-objdump -d --disassemble-symbols=<func> $ELF

  CLASS-OF-BUG shortcuts based on what addr2line returns:

    "??" or address outside kernel range
      -> RIP is in a corrupted region (jumped to free memory or a freed
         page). The corruption already happened; the panic just reports
         the consequence. Look at the BACKTRACE (the caller of the
         corrupt code) — that frame is alive and tells you where the
         bad jump originated.

    Inside a freed allocation (compare against any
    KernelHeapDrainBins / FrameAllocatorDrainPools log lines)
      -> Use-after-free. The freed pointer was dereferenced. The PRIOR
         path that did the free is the bug — look for free without
         clearing the holder.

    Inside the data segment (.data, .bss) at a struct field whose value
    doesn't match what the writer should have stored
      -> Lost-page / lost-slot collision. Two structures share a VA
         (KASLR base collision, slab class collision). See memory
         `serial-log-triage.md` class. Cheap repro: grep for `base=0x...`
         lines in the boot log and look for two structures landing at
         the same address.

==========================================================================
STEP 2 — Determine WHICH allocation was corrupted.

  If the fault is at a known struct's address, identify who allocates
  and frees that struct:

  grep -rn "<StructName>" kernel/ | grep -E "KMalloc|new \w|allocator\."

  Cross-reference with the panic timestamp:
  - Was an alloc-then-free cycle running just before the panic?
  - Was a different subsystem touching nearby memory (page collision)?

==========================================================================
STEP 3 — Add SerialLineGuard-wrapped trace around the suspect allocator.

  Don't trust KLOG_DEBUG for this — the line-sink can re-enter the
  allocator. Use raw arch::SerialWrite + a SerialLineGuard:

    void* MyAlloc(u64 size) {
        void* p = mm::KMalloc(size);
        {
            arch::SerialLineGuard _g;
            arch::SerialWrite("[mytype] ALLOC p=");
            arch::SerialWriteHex(reinterpret_cast<u64>(p));
            arch::SerialWrite(" size=");
            arch::SerialWriteHex(size);
            arch::SerialWrite("\n");
        }
        return p;
    }

  And on free:

    void MyFree(void* p) {
        {
            arch::SerialLineGuard _g;
            arch::SerialWrite("[mytype] FREE p=");
            arch::SerialWriteHex(reinterpret_cast<u64>(p));
            arch::SerialWrite("\n");
        }
        mm::KFree(p);
    }

  Re-run the panic-inducing scenario. Confirm the bad pointer's lifecycle
  in the log:
  - Allocated, freed once, dereferenced (UAF).
  - Allocated twice without intermediate free (double-alloc same slot).
  - Never allocated by the suspect path but the address matches anyway
    (the corruption is collision with a DIFFERENT subsystem's
    allocation — recurse with the OTHER allocator).

==========================================================================
STEP 4 — Use the KASAN-equivalent preset for free-list integrity:

  cmake --preset x86_64-debug-asan      # in-tree KASAN diagnostics
  bash tools/build/wsl-kernel-build-debug.sh  # (edit to use -asan)

  This preset poisons freed frames with 0xDE patterns. If the corruption
  hits readable memory that's 0xDEDEDEDE..., the access is on a freed
  frame — straight UAF.

==========================================================================
STEP 5 — If the bug is alignment-related (SysV ABI / SSE / cache-line):

  Look at the stack dump's RSP & RBP for offsets not divisible by 16.
  A SysV-ABI mismatch (kernel C++ thinks RSP&15==8 at function entry,
  but the actual context-switch trampoline gave it 0) shows up as
  SSE instruction faults (movaps, movdqa) at function entry. See memory
  `sched-stack-align-fix.md` — the fix was in
  kernel/sched/sched.cpp's SchedTaskTrampoline pad quad.

==========================================================================
STEP 6 — Fix at the SOURCE allocator/initializer:

  Bad: nullify the dangling pointer at one call site.
  Good: change the alloc-free contract so freeing the alloc also clears
        the holding pointer (RAII-style wrapper, or explicit pair API
        the caller must use).

==========================================================================
STEP 7 — Validate with at least 20 boots under x86_64-debug-asan AND
20 under x86_64-release (different optimisation may mask or unmask the
bug). For an intermittent fault, post-fix should be 0/40.

==========================================================================
STEP 8 — Save memory:
  Capture: panic vector + RIP shape, the freed-or-collided allocation
  name, the alloc/free path pair that was unbalanced, the fix shape
  (RAII wrapper / clear-on-free / paired alloc API).
```

## Known signatures → known fixes

| Symptom | Likely class | First check |
|---|---|---|
| #PF CR2 inside `.bss`, RIP looks valid | lost-slot collision (KASLR or slab) | grep `base=0x...` in boot log for two structures at same VA |
| #PF CR2 in heap range, page absent | UAF (page freed) | re-run with -asan preset, look for 0xDE pattern |
| Stack dump RSP not 16-byte aligned at fault | SysV ABI break | see `sched-stack-align-fix.md` |
| Slab "magic byte mismatch" panic | adjacent overflow OR double-free | bisect by disabling KASLR (boot with kaslr=off) |
| Triple-fault, RIP inside IDT | IDT itself corrupted | only the BSP page tables can hold the IDT; check FrameAllocator allowlist |
