// DuetOS — x86_64 disassembler fuzz harness.
//
// The in-house disassembler (kernel/debug/disasm.{h,cpp}) is on
// the crash-dump path — it decodes arbitrary instruction bytes
// from a faulting RIP so the post-mortem can show one or two
// rows of context. A decode bug there compounds the crash and
// can take down the dump itself, so it warrants its own
// host-fuzz coverage.
//
// `DecodeStream` accepts a buffer + cap + VA and writes up to
// `row_cap` `DecodedInsn` rows. The harness drives the public
// entry with bounded inputs; ASan catches any read past the
// supplied length, UBSan catches any in-decoder integer
// overflow. The disassembler is "allocation-free, IRQ-safe,
// panic-safe" per the header — no shimming required beyond
// the existing log/klog no-ops.

#include "debug/disasm.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size > 4096)
        return 0;

    // 256 rows is enough to walk a 4 KiB buffer at the
    // minimum legal x86_64 instruction length of 1. Static so
    // the harness's hot loop doesn't burn stack frames.
    static duetos::debug::disasm::DecodedInsn rows[256];

    // Synthetic but plausible VA in the kernel canonical range.
    // The decoder uses `va` to compute relative-branch absolute
    // targets stitched into the operands field; using a non-zero
    // address exercises the formatter path that bare-zero would
    // skip via simple-case fast paths.
    constexpr duetos::u64 kVa = 0xffffffff80100000ULL;

    (void)duetos::debug::disasm::DecodeStream(reinterpret_cast<const duetos::u8*>(data), static_cast<duetos::u64>(size),
                                              kVa, rows, sizeof(rows) / sizeof(rows[0]));
    return 0;
}
