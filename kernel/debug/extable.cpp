#include "extable.h"

#include "../arch/x86_64/serial.h"
#include "../core/klog.h"
#include "../core/panic.h"

namespace customos::debug
{

namespace
{

constinit ExtableEntry g_entries[kMaxExtableEntries] = {};
constinit u32 g_entry_count = 0;

// Single bit that the trap handler checks to avoid re-entering
// the lookup during a double-fault or IST trap. If a trap lands
// while we're walking the table (really should never happen at
// v0 scale, but defense-in-depth), the handler bails to the
// default Panic path instead of risking infinite recursion.
constinit bool g_in_lookup = false;

} // namespace

bool KernelExtableRegisterWithDomain(u64 rip_start, u64 rip_end, u64 fixup_rip, const char* tag, u32 domain_id)
{
    if (rip_start >= rip_end || fixup_rip == 0)
        return false;
    if (g_entry_count >= kMaxExtableEntries)
    {
        arch::SerialWrite("[extable] registry full; refused entry tag=");
        arch::SerialWrite(tag ? tag : "?");
        arch::SerialWrite("\n");
        return false;
    }
    ExtableEntry& e = g_entries[g_entry_count++];
    e.rip_start = rip_start;
    e.rip_end = rip_end;
    e.fixup_rip = fixup_rip;
    e.tag = (tag != nullptr) ? tag : "?";
    e.domain_id = domain_id;
    arch::SerialWrite("[extable] register tag=");
    arch::SerialWrite(e.tag);
    arch::SerialWrite(" rip=[");
    arch::SerialWriteHex(rip_start);
    arch::SerialWrite(",");
    arch::SerialWriteHex(rip_end);
    arch::SerialWrite(") fixup=");
    arch::SerialWriteHex(fixup_rip);
    if (domain_id != kExtableNoDomain)
    {
        arch::SerialWrite(" domain=");
        arch::SerialWriteHex(domain_id);
    }
    arch::SerialWrite("\n");
    return true;
}

bool KernelExtableRegister(u64 rip_start, u64 rip_end, u64 fixup_rip, const char* tag)
{
    return KernelExtableRegisterWithDomain(rip_start, rip_end, fixup_rip, tag, kExtableNoDomain);
}

u64 KernelExtableFindFixup(u64 rip)
{
    const ExtableEntry* e = KernelExtableFindEntry(rip);
    return (e != nullptr) ? e->fixup_rip : 0;
}

const ExtableEntry* KernelExtableFindEntry(u64 rip)
{
    if (g_in_lookup)
        return nullptr; // double-fault guard
    g_in_lookup = true;
    const ExtableEntry* hit = nullptr;
    for (u32 i = 0; i < g_entry_count; ++i)
    {
        const ExtableEntry& e = g_entries[i];
        if (rip >= e.rip_start && rip < e.rip_end)
        {
            hit = &e;
            break;
        }
    }
    g_in_lookup = false;
    return hit;
}

u32 KernelExtableEntryCount()
{
    return g_entry_count;
}

const ExtableEntry* KernelExtableEntryAt(u32 i)
{
    if (i >= g_entry_count)
        return nullptr;
    return &g_entries[i];
}

// --- Self-test ----------------------------------------------------

void ExtableSelfTest()
{
    KLOG_TRACE_SCOPE("debug/extable", "SelfTest");

    // Simulate a registration and verify the lookup path. We can't
    // safely trigger a real trap from inside this self-test (the
    // trap handler path would actually execute the fixup, and a
    // fake fixup on a real stack frame is a crash waiting to
    // happen), so we just check the bookkeeping.
    const u32 before = g_entry_count;
    const u64 fake_start = 0xFFFFFFFF8EADBEEFULL;
    const u64 fake_end = fake_start + 0x10;
    const u64 fake_fixup = 0xFFFFFFFF8C0DEF00ULL;
    const bool ok = KernelExtableRegister(fake_start, fake_end, fake_fixup, "selftest.synth");
    if (!ok)
    {
        core::PanicWithValue("debug/extable", "SelfTest: register failed", g_entry_count);
    }
    const u64 mid = fake_start + 4;
    const u64 hit = KernelExtableFindFixup(mid);
    if (hit != fake_fixup)
    {
        core::PanicWithValue("debug/extable", "SelfTest: mid-range lookup mismatch", hit);
    }
    const u64 past = fake_end + 0x1000;
    const u64 miss = KernelExtableFindFixup(past);
    if (miss != 0)
    {
        core::PanicWithValue("debug/extable", "SelfTest: out-of-range should miss", miss);
    }
    // Roll back the synthetic entry so it doesn't leak a bogus
    // rip range into the trap handler. Safe because nobody else
    // has touched the table since we added it.
    if (g_entry_count == before + 1)
        g_entry_count = before;

    // Domain-id round-trip: a row registered with a domain id
    // should report that id back via FindEntry. Use 0x12345678 —
    // an obviously-synthetic FaultDomainId that no real domain
    // will ever take (FaultDomainRegister hands out small
    // sequential ids).
    const u64 dom_start = 0xFFFFFFFF8DEADC0DULL;
    const u64 dom_end = dom_start + 0x10;
    const u64 dom_fixup = 0xFFFFFFFF8C0DEF80ULL;
    const u32 dom_id = 0x12345678;
    if (!KernelExtableRegisterWithDomain(dom_start, dom_end, dom_fixup, "selftest.dom", dom_id))
    {
        core::PanicWithValue("debug/extable", "SelfTest: register-with-domain failed", g_entry_count);
    }
    const ExtableEntry* found = KernelExtableFindEntry(dom_start + 4);
    if (found == nullptr)
    {
        core::PanicWithValue("debug/extable", "SelfTest: domain row not found", 0);
    }
    if (found->domain_id != dom_id)
    {
        core::PanicWithValue("debug/extable", "SelfTest: domain_id round-trip mismatch", found->domain_id);
    }
    if (g_entry_count == before + 1)
        g_entry_count = before;

    arch::SerialWrite("[extable-selftest] PASS (register + hit + miss + domain-id; ");
    arch::SerialWriteHex(g_entry_count);
    arch::SerialWrite(" entries live)\n");
}

} // namespace customos::debug
