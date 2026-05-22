#include "diag/hexdump.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "core/panic.h"
#include "util/symbols.h"

namespace duetos::core
{

namespace
{

// Plausible kernel-VA ranges. Restricted to the higher-half kernel
// region (direct map + MMIO arena). The low 1 GiB identity map IS
// mapped, but in long mode + SMAP it's reserved for user pages once
// userland is online — a kernel read from a low VA when the current
// CR3 maps that VA into ring 3 trips SMAP and #PFs us. Refusing the
// low half outright keeps every consumer (trap dispatcher dumping a
// user RIP, panic dumping a corrupt RBP) from triggering a nested
// fault. Boot-era kernel addresses are always already higher-half by
// the time anything that calls these dumpers can run.
// Range covers the direct map + MMIO arena + kernel stack arena.
// The original upper bound (0xFFFFFFFFE0000000) cut off EXACTLY at
// the start of the kernel stack arena (see kKernelStackArenaBase in
// mm/kstack.h), which meant the panic dump's `[fault-stack]` window
// reported `<unreadable>` for every task whose fault rsp lived in
// the kstack arena — i.e. every task other than the boot task.
// Observed 2026-05-22 on the SMP=8 saturation UAF as
// `[fault-stack] stack@0xffffffffe0120fc0 (0x10 quads):
//     0xffffffffe0120fc0 : <unreadable>` — the bug's call chain
// was sitting right there in memory; the bound just wouldn't let
// us read it.
//
// Extending to 0xFFFFFFFFFFFFFFFF covers the entire higher-half
// canonical range; the kernel never maps anything outside it, so
// no false-positive: any read above kHigherHalfStart either hits a
// kernel-mapped page (succeeds) or an unmapped page (legitimate
// #PF, classifier downgrades the fault, no recursive trap).
constexpr u64 kHigherHalfStart = 0xFFFFFFFF80000000ULL; // direct map
constexpr u64 kHigherHalfEnd = 0xFFFFFFFFFFFFFFFFULL;   // through end of canonical higher half
constexpr u64 kPageSize = 4096;
constexpr u64 kPageMask = ~(kPageSize - 1);

void WriteHexByte(u8 b)
{
    constexpr char kHex[] = "0123456789ABCDEF";
    char out[3] = {kHex[(b >> 4) & 0xF], kHex[b & 0xF], 0};
    arch::SerialWrite(out);
}

void WriteAsciiByte(u8 b)
{
    char out[2] = {static_cast<char>((b >= 0x20 && b < 0x7F) ? b : '.'), 0};
    arch::SerialWrite(out);
}

} // namespace

bool PlausibleKernelAddress(u64 va)
{
    if (va == 0)
    {
        return false;
    }
    // Use <= so the very last byte of the canonical higher half
    // (0xFFFFFFFFFFFFFFFF as kHigherHalfEnd) is still considered
    // plausible — single u64 reads at that edge are rare but
    // legitimate (e.g. an instruction RIP near the end of the
    // canonical range).
    if (va >= kHigherHalfStart && va <= kHigherHalfEnd)
    {
        return true;
    }
    return false;
}

void DumpInstructionBytes(const char* tag, u64 addr, u32 len)
{
    if (len > kMaxInstructionDumpBytes)
    {
        len = kMaxInstructionDumpBytes;
    }
    arch::SerialWrite("  [");
    arch::SerialWrite(tag);
    arch::SerialWrite("] instr@");
    arch::SerialWriteHex(addr);
    arch::SerialWrite(" :");
    if (!PlausibleKernelAddress(addr))
    {
        arch::SerialWrite(" <skipped: address not in kernel range>\n");
        return;
    }
    // If the range crosses a page boundary, only dump the bytes in
    // the starting page — the next page may be unmapped or outside
    // kernel range, and stopping mid-instruction is better than
    // faulting on the dump.
    const u64 page_of_start = addr & kPageMask;
    const auto* p = reinterpret_cast<const u8*>(addr);
    for (u32 i = 0; i < len; ++i)
    {
        const u64 byte_va = addr + i;
        if ((byte_va & kPageMask) != page_of_start)
        {
            arch::SerialWrite(" ..");
            break;
        }
        arch::SerialWrite(" ");
        WriteHexByte(p[i]);
    }
    arch::SerialWrite("\n");
}

void DumpHexRegion(const char* tag, u64 addr, u32 len)
{
    DumpHexRegionSafe(tag, addr, len, 0);
}

void DumpHexRegionSafe(const char* tag, u64 addr, u32 len, u64 skip_page_va)
{
    if (len > kMaxRegionDumpBytes)
    {
        len = kMaxRegionDumpBytes;
    }
    if (len == 0)
    {
        return;
    }
    constexpr u32 kBytesPerLine = 16;
    const u64 skip_page_base = skip_page_va & kPageMask;

    u32 offset = 0;
    while (offset < len)
    {
        const u64 line_va = addr + offset;
        const u32 line_len = (len - offset < kBytesPerLine) ? (len - offset) : kBytesPerLine;

        arch::SerialWrite("  [");
        arch::SerialWrite(tag);
        arch::SerialWrite("] ");
        arch::SerialWriteHex(line_va);
        arch::SerialWrite(" :");

        const bool plausible = PlausibleKernelAddress(line_va);
        const bool in_skip_page = (skip_page_va != 0) && ((line_va & kPageMask) == skip_page_base);

        if (!plausible)
        {
            arch::SerialWrite(" <unreadable: VA not in kernel range>\n");
        }
        else if (in_skip_page)
        {
            arch::SerialWrite(" <skipped: faulting page>\n");
        }
        else
        {
            const auto* p = reinterpret_cast<const u8*>(line_va);
            // Hex column.
            for (u32 i = 0; i < line_len; ++i)
            {
                arch::SerialWrite(" ");
                WriteHexByte(p[i]);
            }
            // Pad short final lines so ASCII column aligns.
            for (u32 i = line_len; i < kBytesPerLine; ++i)
            {
                arch::SerialWrite("   ");
            }
            // ASCII column.
            arch::SerialWrite("  |");
            for (u32 i = 0; i < line_len; ++i)
            {
                WriteAsciiByte(p[i]);
            }
            arch::SerialWrite("|\n");
        }
        offset += line_len;
    }
}

namespace
{

void Expect(bool cond, const char* what)
{
    if (cond)
    {
        return;
    }
    arch::SerialWrite("[hexdump-selftest] FAIL ");
    arch::SerialWrite(what);
    arch::SerialWrite("\n");
    Panic("core/hexdump", "HexdumpSelfTest assertion failed");
}

} // namespace

void HexdumpSelfTest()
{
    KLOG_TRACE_SCOPE("core/hexdump", "HexdumpSelfTest");

    // ----- PlausibleKernelAddress -----
    // NULL is rejected outright — every consumer would fault if we
    // accepted it.
    Expect(!PlausibleKernelAddress(0), "addr=0 rejected");

    // Low-half addresses (user / boot identity map) always reject so
    // the trap dispatcher never deref's a user RIP under SMAP.
    Expect(!PlausibleKernelAddress(0x1000), "low VA 0x1000 rejected");
    Expect(!PlausibleKernelAddress(0x40000000), "user VA rejected");
    Expect(!PlausibleKernelAddress(0x7FFFE000), "ring-3 stack VA rejected");
    Expect(!PlausibleKernelAddress(0xFFFFFFFE), "32-bit max rejected");

    // Higher-half boundary: namespace-anonymous kHigherHalfStart inclusive,
    // kHigherHalfEnd inclusive (the predicate uses <=). Asserting against
    // the canonical values (re-stated as locals to make the test
    // self-documenting without shadowing the file-scope constants).
    // Extended upward 2026-05-22 to include the kernel stack arena
    // (0xFFFFFFFFE0000000+), which was previously rejected — the panic
    // dump's stack window emitted `<unreadable>` for every fault
    // whose rsp landed in the kstack arena (every non-boot task).
    constexpr u64 kHigherHalfStartCanonical = 0xFFFFFFFF80000000ULL;
    constexpr u64 kHigherHalfEndCanonical = 0xFFFFFFFFFFFFFFFFULL;
    constexpr u64 kKstackArenaBaseCanonical = 0xFFFFFFFFE0000000ULL;
    static_assert(kHigherHalfStart == kHigherHalfStartCanonical, "higher-half start drifted");
    static_assert(kHigherHalfEnd == kHigherHalfEndCanonical, "higher-half end drifted");
    Expect(!PlausibleKernelAddress(kHigherHalfStartCanonical - 1), "below higher half rejected");
    Expect(PlausibleKernelAddress(kHigherHalfStartCanonical), "higher-half start accepted");
    Expect(PlausibleKernelAddress(kHigherHalfStartCanonical + 0x10000), "kernel direct map accepted");
    Expect(PlausibleKernelAddress(0xFFFFFFFFDFFFFFFFULL), "MMIO arena cap accepted");
    Expect(PlausibleKernelAddress(kKstackArenaBaseCanonical), "kstack arena base accepted");
    Expect(PlausibleKernelAddress(kKstackArenaBaseCanonical + 0x120000), "kstack arena mid accepted");
    Expect(PlausibleKernelAddress(kHigherHalfEndCanonical), "u64 max accepted (top of canonical)");

    // ----- DumpInstructionBytes against a known-mapped kernel symbol -----
    // `&HexdumpSelfTest` itself sits in .text, which is mapped R+X
    // and lives in the higher half. Dumping the first 8 bytes of our
    // own function exercises the formatter end-to-end. The byte
    // values aren't asserted (they vary with optimisation level) —
    // we just need the call to return without faulting.
    const u64 self_va = reinterpret_cast<u64>(&HexdumpSelfTest);
    Expect(PlausibleKernelAddress(self_va), "self_va in kernel range");
    DumpInstructionBytes("hexdump-selftest", self_va, 8);

    // ----- DumpHexRegionSafe against an unmapped low VA -----
    // Should print "<unreadable>" rather than fault; the call below
    // not panicking IS the assertion.
    DumpHexRegionSafe("hexdump-selftest", 0x1000, 16, /*skip_page_va=*/0);

    arch::SerialWrite("[hexdump-selftest] PASS (PlausibleKernelAddress + dump formatters)\n");
}

void DumpStackWindow(const char* tag, u64 rsp, u32 quad_count)
{
    arch::SerialWrite("  [");
    arch::SerialWrite(tag);
    arch::SerialWrite("] stack@");
    arch::SerialWriteHex(rsp);
    arch::SerialWrite(" (");
    arch::SerialWriteHex(static_cast<u64>(quad_count));
    arch::SerialWrite(" quads):\n");
    // 8-byte align — unaligned RSP is a bug on x86_64 ABI entry, but
    // stopping the dump entirely is worse than rounding down.
    if ((rsp & 0x7) != 0)
    {
        rsp &= ~0x7ULL;
    }
    // Page-clamp guard: a kernel-stack-arena slot is exactly one
    // page of usable stack with an UNMAPPED guard page above the
    // top byte (see mm/kstack.h). A `rsp` that's already near the
    // top of its slot must not have the window run into the guard
    // page — that would re-trap on a #PF and bury the dump in the
    // recursive-panic short-circuit. Observed 2026-05-22 on the
    // SMP=8 UAF: the rsp landed at offset 0xfc0 of a stack page,
    // so quad 8 of the window would have crossed into 0xN000 (the
    // guard page), which is exactly cr2 the recursive guard-page
    // panic reported. Clamp to "stay in the starting page" — the
    // most diagnostic-rich bytes are the first few quads anyway.
    constexpr u64 kPageMaskLocal = ~(kPageSize - 1ULL);
    const u64 page_top = (rsp & kPageMaskLocal) + kPageSize;
    for (u32 i = 0; i < quad_count; ++i)
    {
        const u64 va = rsp + static_cast<u64>(i) * 8;
        if (va + 8 > page_top)
        {
            arch::SerialWrite("    ");
            arch::SerialWriteHex(va);
            arch::SerialWrite(" : <page-boundary: clamping window to stay off the kstack guard page>\n");
            break;
        }
        if (!PlausibleKernelAddress(va))
        {
            arch::SerialWrite("    ");
            arch::SerialWriteHex(va);
            arch::SerialWrite(" : <unreadable>\n");
            break;
        }
        const u64 value = *reinterpret_cast<const u64*>(va);
        arch::SerialWrite("    ");
        arch::SerialWriteHex(va);
        arch::SerialWrite(" : ");
        WriteAddressWithSymbol(value);
        arch::SerialWrite("\n");
    }
}

} // namespace duetos::core
