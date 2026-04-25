#include "diag_decode.h"

#include "../arch/x86_64/gdt.h"
#include "../arch/x86_64/hpet.h"
#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/timer.h"
#include "../cpu/percpu.h"
#include "../sched/sched.h"
#include "hexdump.h"
#include "symbols.h"

/*
 * DuetOS — diagnostic decoders.
 *
 * One file, one responsibility: take a raw 64-bit value and write a
 * human-readable annotation of what it means after the hex. Every
 * function calls only into arch::Serial* and the symbol resolver,
 * so they're safe from any context.
 */

namespace duetos::core
{

namespace
{

inline void WriteDecimal(u64 v)
{
    if (v == 0)
    {
        arch::SerialWriteByte('0');
        return;
    }
    char buf[20];
    int n = 0;
    while (v > 0)
    {
        buf[n++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    while (n > 0)
    {
        arch::SerialWriteByte(static_cast<u8>(buf[--n]));
    }
}

// Emit a labelled flag iff the bit is set. The first set flag
// is preceded by no separator; subsequent ones get '|'. Caller
// owns the surrounding brackets and the "first" flag tracker.
inline void EmitFlag(bool set, const char* name, bool& first)
{
    if (!set)
    {
        return;
    }
    if (!first)
    {
        arch::SerialWriteByte('|');
    }
    arch::SerialWrite(name);
    first = false;
}

} // namespace

void WriteCr0Bits(u64 value)
{
    arch::SerialWrite(" [");
    bool first = true;
    EmitFlag(value & (1ULL << 0), "PE", first);
    EmitFlag(value & (1ULL << 1), "MP", first);
    EmitFlag(value & (1ULL << 2), "EM", first);
    EmitFlag(value & (1ULL << 3), "TS", first);
    EmitFlag(value & (1ULL << 4), "ET", first);
    EmitFlag(value & (1ULL << 5), "NE", first);
    EmitFlag(value & (1ULL << 16), "WP", first);
    EmitFlag(value & (1ULL << 18), "AM", first);
    EmitFlag(value & (1ULL << 29), "NW", first);
    EmitFlag(value & (1ULL << 30), "CD", first);
    EmitFlag(value & (1ULL << 31), "PG", first);
    if (first)
    {
        arch::SerialWrite("none");
    }
    arch::SerialWrite("]");
}

void WriteCr4Bits(u64 value)
{
    arch::SerialWrite(" [");
    bool first = true;
    EmitFlag(value & (1ULL << 0), "VME", first);
    EmitFlag(value & (1ULL << 1), "PVI", first);
    EmitFlag(value & (1ULL << 2), "TSD", first);
    EmitFlag(value & (1ULL << 3), "DE", first);
    EmitFlag(value & (1ULL << 4), "PSE", first);
    EmitFlag(value & (1ULL << 5), "PAE", first);
    EmitFlag(value & (1ULL << 6), "MCE", first);
    EmitFlag(value & (1ULL << 7), "PGE", first);
    EmitFlag(value & (1ULL << 8), "PCE", first);
    EmitFlag(value & (1ULL << 9), "OSFXSR", first);
    EmitFlag(value & (1ULL << 10), "OSXMMEXCPT", first);
    EmitFlag(value & (1ULL << 11), "UMIP", first);
    EmitFlag(value & (1ULL << 13), "VMXE", first);
    EmitFlag(value & (1ULL << 14), "SMXE", first);
    EmitFlag(value & (1ULL << 16), "FSGSBASE", first);
    EmitFlag(value & (1ULL << 17), "PCIDE", first);
    EmitFlag(value & (1ULL << 18), "OSXSAVE", first);
    EmitFlag(value & (1ULL << 20), "SMEP", first);
    EmitFlag(value & (1ULL << 21), "SMAP", first);
    EmitFlag(value & (1ULL << 22), "PKE", first);
    EmitFlag(value & (1ULL << 23), "CET", first);
    if (first)
    {
        arch::SerialWrite("none");
    }
    arch::SerialWrite("]");
}

void WriteRflagsBits(u64 value)
{
    arch::SerialWrite(" [");
    bool first = true;
    EmitFlag(value & (1ULL << 0), "CF", first);
    EmitFlag(value & (1ULL << 2), "PF", first);
    EmitFlag(value & (1ULL << 4), "AF", first);
    EmitFlag(value & (1ULL << 6), "ZF", first);
    EmitFlag(value & (1ULL << 7), "SF", first);
    EmitFlag(value & (1ULL << 8), "TF", first);
    EmitFlag(value & (1ULL << 9), "IF", first);
    EmitFlag(value & (1ULL << 10), "DF", first);
    EmitFlag(value & (1ULL << 11), "OF", first);
    const u64 iopl = (value >> 12) & 0x3;
    if (iopl != 0)
    {
        if (!first)
        {
            arch::SerialWriteByte('|');
        }
        arch::SerialWrite("IOPL=");
        WriteDecimal(iopl);
        first = false;
    }
    EmitFlag(value & (1ULL << 14), "NT", first);
    EmitFlag(value & (1ULL << 16), "RF", first);
    EmitFlag(value & (1ULL << 17), "VM", first);
    EmitFlag(value & (1ULL << 18), "AC", first);
    EmitFlag(value & (1ULL << 19), "VIF", first);
    EmitFlag(value & (1ULL << 20), "VIP", first);
    EmitFlag(value & (1ULL << 21), "ID", first);
    if (first)
    {
        arch::SerialWrite("none");
    }
    arch::SerialWrite("]");
}

void WriteEferBits(u64 value)
{
    arch::SerialWrite(" [");
    bool first = true;
    EmitFlag(value & (1ULL << 0), "SCE", first);
    EmitFlag(value & (1ULL << 8), "LME", first);
    EmitFlag(value & (1ULL << 10), "LMA", first);
    EmitFlag(value & (1ULL << 11), "NXE", first);
    EmitFlag(value & (1ULL << 12), "SVME", first);
    EmitFlag(value & (1ULL << 13), "LMSLE", first);
    EmitFlag(value & (1ULL << 14), "FFXSR", first);
    EmitFlag(value & (1ULL << 15), "TCE", first);
    if (first)
    {
        arch::SerialWrite("none");
    }
    arch::SerialWrite("]");
}

void WriteSegmentSelectorBits(u64 selector)
{
    const u64 rpl = selector & 0x3;
    const bool ldt = (selector & 0x4) != 0;
    const u64 idx = (selector >> 3) & 0x1FFF;

    arch::SerialWrite(" [ring=");
    WriteDecimal(rpl);
    arch::SerialWrite(ldt ? " LDT idx=" : " GDT idx=");
    WriteDecimal(idx);

    // Map the index back to the canonical kernel GDT layout from
    // `arch/x86_64/gdt.h`. Anything else is unknown — the operator
    // gets the index alone, which still beats a bare hex selector.
    const char* role = nullptr;
    if (selector == 0)
    {
        role = "null";
    }
    else if (selector == arch::kKernelCodeSelector)
    {
        role = "kernel-code";
    }
    else if (selector == arch::kKernelDataSelector)
    {
        role = "kernel-data";
    }
    else if (selector == arch::kUserCodeSelector)
    {
        role = "user-code";
    }
    else if (selector == arch::kUserDataSelector)
    {
        role = "user-data";
    }
    else if ((selector & ~0x3ULL) == arch::kTssSelector)
    {
        role = "tss";
    }

    if (role != nullptr)
    {
        arch::SerialWrite(" (");
        arch::SerialWrite(role);
        arch::SerialWrite(")");
    }
    arch::SerialWrite("]");
}

void WritePageFaultErrBits(u64 err)
{
    arch::SerialWrite(" [");
    arch::SerialWrite((err & 0x01) ? "present" : "notpresent");
    arch::SerialWrite((err & 0x02) ? "|write" : "|read");
    arch::SerialWrite((err & 0x04) ? "|user" : "|kernel");
    if (err & 0x08)
    {
        arch::SerialWrite("|rsvd");
    }
    if (err & 0x10)
    {
        arch::SerialWrite("|instr");
    }
    if (err & 0x20)
    {
        arch::SerialWrite("|pkey");
    }
    if (err & 0x40)
    {
        arch::SerialWrite("|ss");
    }
    arch::SerialWrite("]");
}

void WriteUptimeReadable()
{
    // HPET path. Same conversion as klog — counter * fs/1e9 yields
    // microseconds; we render millisecond precision, falling back to
    // seconds for long uptimes so the number stays scannable.
    u64 us = 0;
    const u64 hpet_counter = arch::HpetReadCounter();
    const u32 period_fs = arch::HpetPeriodFemtoseconds();
    if (hpet_counter != 0 && period_fs != 0)
    {
        const u64 ticks_per_us = 1'000'000'000ULL / period_fs;
        if (ticks_per_us != 0)
        {
            us = hpet_counter / ticks_per_us;
        }
    }
    if (us == 0)
    {
        // Pre-HPET: scheduler tick is 10 ms (kTickFrequencyHz=100).
        us = arch::TimerTicks() * 10'000ULL;
    }

    if (us >= 60'000'000ULL)
    {
        const u64 sec_total = us / 1'000'000ULL;
        const u64 ms_frac = (us / 1000ULL) % 1000;
        const u64 minutes = sec_total / 60;
        const u64 seconds = sec_total % 60;
        WriteDecimal(minutes);
        arch::SerialWrite("m ");
        WriteDecimal(seconds);
        arch::SerialWriteByte('.');
        if (ms_frac < 100)
            arch::SerialWriteByte('0');
        if (ms_frac < 10)
            arch::SerialWriteByte('0');
        WriteDecimal(ms_frac);
        arch::SerialWrite("s");
        return;
    }
    if (us >= 1'000'000ULL)
    {
        const u64 sec_whole = us / 1'000'000ULL;
        const u64 ms_frac = (us / 1000ULL) % 1000;
        WriteDecimal(sec_whole);
        arch::SerialWriteByte('.');
        if (ms_frac < 100)
            arch::SerialWriteByte('0');
        if (ms_frac < 10)
            arch::SerialWriteByte('0');
        WriteDecimal(ms_frac);
        arch::SerialWrite(" s");
        return;
    }
    if (us >= 1000)
    {
        const u64 ms_whole = us / 1000;
        const u64 us_frac = us % 1000;
        WriteDecimal(ms_whole);
        arch::SerialWriteByte('.');
        if (us_frac < 100)
            arch::SerialWriteByte('0');
        if (us_frac < 10)
            arch::SerialWriteByte('0');
        WriteDecimal(us_frac);
        arch::SerialWrite(" ms");
        return;
    }
    WriteDecimal(us);
    arch::SerialWrite(" us");
}

void WriteCurrentTaskLabel()
{
    cpu::PerCpu* pcpu = cpu::CurrentCpu();
    if (pcpu == nullptr)
    {
        arch::SerialWrite("<unknown> (pre-percpu)");
        return;
    }
    sched::Task* task = pcpu->current_task;
    if (task == nullptr)
    {
        arch::SerialWrite("<idle> (pre-sched)");
        return;
    }
    const char* name = sched::TaskName(task);
    if (name == nullptr || name[0] == 0)
    {
        name = "<noname>";
    }
    arch::SerialWrite(name);
    arch::SerialWriteByte('#');
    WriteDecimal(sched::TaskId(task));
}

void WriteCr3Decoded(u64 value)
{
    // CR3 layout (long mode, no PCID):
    //   bits  0..11   PCID (when CR4.PCIDE=1) else reserved/PWT/PCD
    //   bits 12..51   PML4 base (4 KiB aligned)
    const u64 pml4_base = value & ~0xFFFULL;
    const u64 low12 = value & 0xFFFULL;
    arch::SerialWrite(" [pml4=0x");
    // Compact hex without leading zeros — pml4 base is always ≥ 4 KiB
    // so we know it's non-zero in any healthy CR3.
    static constexpr char kDigits[] = "0123456789abcdef";
    int shift = 60;
    while (shift > 0 && ((pml4_base >> shift) & 0xF) == 0)
    {
        shift -= 4;
    }
    for (; shift >= 0; shift -= 4)
    {
        arch::SerialWriteByte(static_cast<u8>(kDigits[(pml4_base >> shift) & 0xF]));
    }
    arch::SerialWrite(" pcid=");
    WriteDecimal(low12);
    arch::SerialWrite("]");
}

void WriteSymbolIfCode(u64 value)
{
    if (!PlausibleKernelAddress(value))
    {
        return;
    }
    SymbolResolution res{};
    if (ResolveAddress(value, &res))
    {
        WriteResolvedAddress(res);
    }
}

void WritePteFlags(u64 flags)
{
    arch::SerialWrite(" [");
    bool first = true;
    EmitFlag(flags & (1ULL << 0), "P", first);
    EmitFlag(flags & (1ULL << 1), "RW", first);
    EmitFlag(flags & (1ULL << 2), "US", first);
    EmitFlag(flags & (1ULL << 3), "PWT", first);
    EmitFlag(flags & (1ULL << 4), "PCD", first);
    EmitFlag(flags & (1ULL << 5), "A", first);
    EmitFlag(flags & (1ULL << 6), "D", first);
    // Bit 7 is "PS" in PDE/PDPTE (page size = huge page) but "PAT" in
    // a leaf PTE. The two contexts share a printer here so the label
    // is the disjunction; the surrounding log line tells the reader
    // which level the flags belong to.
    EmitFlag(flags & (1ULL << 7), "PS/PAT", first);
    EmitFlag(flags & (1ULL << 8), "G", first);
    EmitFlag(flags & (1ULL << 63), "NX", first);
    if (first)
    {
        arch::SerialWrite("none");
    }
    arch::SerialWrite("]");
}

} // namespace duetos::core
