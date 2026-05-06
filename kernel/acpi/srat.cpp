#include "acpi/srat.h"

#include "debug/probes.h"
#include "log/klog.h"

namespace duetos::acpi::srat
{

namespace
{

// ACPI SDT header prefix — we only need signature, length, and
// checksum to validate the table. Full layout matches what
// acpi.cpp uses; we redeclare locally to keep srat.cpp standalone
// rather than reach into acpi.cpp's file-local types.
struct [[gnu::packed]] SdtPrefix
{
    char signature[4];
    u32 length;
    u8 revision;
    u8 checksum;
    char oem_id[6];
    char oem_table_id[8];
    u32 oem_revision;
    u32 creator_id;
    u32 creator_revision;
};

// SRAT body header — 12 bytes following the SDT header. Two
// reserved fields per ACPI spec; we don't consume them, but the
// affinity records start at SRAT base + sizeof(SdtPrefix) + 12.
struct [[gnu::packed]] SratBody
{
    u32 reserved1; // must be 1 per spec
    u64 reserved2;
};

constexpr u64 kSratBodyOffset = sizeof(SdtPrefix) + sizeof(SratBody);

// Affinity record subtypes we care about.
constexpr u8 kSubtypeLapicAffinity = 0;
constexpr u8 kSubtypeMemoryAffinity = 1;
constexpr u8 kSubtypeX2ApicAffinity = 2;

// Subtype-0 record — Processor Local APIC/SAPIC Affinity, 16 bytes.
struct [[gnu::packed]] LapicAffinity
{
    u8 type;          // == 0
    u8 length;        // == 16
    u8 proximity_low; // low byte of 32-bit proximity domain
    u8 apic_id;
    u32 flags; // bit 0 = enabled
    u8 local_sapic_eid;
    u8 proximity_high[3]; // bytes 1..3 of proximity domain
    u32 clock_domain;
};
static_assert(sizeof(LapicAffinity) == 16, "LapicAffinity record must be 16 bytes");

// Subtype-1 record — Memory Affinity, 40 bytes.
struct [[gnu::packed]] MemoryAffinity
{
    u8 type;   // == 1
    u8 length; // == 40
    u32 proximity_domain;
    u16 reserved;
    u64 base_addr;
    u64 length_bytes;
    u32 reserved2;
    u32 flags; // bit 0 = enabled, bit 1 = hot-pluggable, bit 2 = non-volatile
    u64 reserved3;
};
static_assert(sizeof(MemoryAffinity) == 40, "MemoryAffinity record must be 40 bytes");

// Subtype-2 record — Processor Local x2APIC Affinity, 24 bytes.
struct [[gnu::packed]] X2ApicAffinity
{
    u8 type;   // == 2
    u8 length; // == 24
    u16 reserved;
    u32 proximity_domain;
    u32 x2apic_id;
    u32 flags; // bit 0 = enabled
    u32 clock_domain;
    u32 reserved2;
};
static_assert(sizeof(X2ApicAffinity) == 24, "X2ApicAffinity record must be 24 bytes");

constexpr u32 kAffinityFlagEnabled = 1U << 0;

// Per-APIC-ID lookup table. kNoNode means "no SRAT entry".
constinit u8 g_apic_to_node[kMaxApicId] = {};

// Domain remap: each entry is the raw proximity-domain value seen
// in the SRAT, in the order encountered. A domain's dense index is
// its position in this array. A value of 0xFFFFFFFF means "slot
// unused".
constinit u32 g_domain_remap[kMaxNumaNodes] = {};
constinit u8 g_node_count = 0;

// Memory-affinity records. Filled by WalkRecords for each enabled
// subtype-1 entry. Indexed by `node` in dense form (same namespace
// as g_apic_to_node).
constinit MemoryRange g_memory_ranges[kMaxMemoryRanges] = {};
constinit u8 g_memory_range_count = 0;

constinit bool g_present = false;
constinit bool g_inited = false;

// Reset all state. Called at the head of SratInit so re-running
// the parser (defensive idempotency) starts from a known floor.
void ResetState()
{
    for (u32 i = 0; i < kMaxApicId; ++i)
    {
        g_apic_to_node[i] = kNoNode;
    }
    for (u8 i = 0; i < kMaxNumaNodes; ++i)
    {
        g_domain_remap[i] = 0xFFFFFFFFu;
    }
    for (u8 i = 0; i < kMaxMemoryRanges; ++i)
    {
        g_memory_ranges[i] = MemoryRange{};
    }
    g_node_count = 0;
    g_memory_range_count = 0;
    g_present = false;
}

// Map a raw proximity-domain value to a dense 0..N-1 index. Adds
// a new slot if the domain hasn't been seen before. Returns
// kNoNode if the remap table is full (rare — capped at
// kMaxNumaNodes; on a typical x86_64 desktop we see 1, dual-
// socket workstations 2).
u8 RemapDomain(u32 raw_domain)
{
    for (u8 i = 0; i < g_node_count; ++i)
    {
        if (g_domain_remap[i] == raw_domain)
        {
            return i;
        }
    }
    if (g_node_count >= kMaxNumaNodes)
    {
        // Remap table exhausted. Fire the regression probe but
        // don't panic — the affected CPU just gets cluster=0.
        KBP_PROBE_V(::duetos::debug::ProbeId::kTopologyParseFailed, raw_domain);
        return kNoNode;
    }
    g_domain_remap[g_node_count] = raw_domain;
    return g_node_count++;
}

bool ChecksumOk(const u8* p, u32 length)
{
    u8 sum = 0;
    for (u32 i = 0; i < length; ++i)
    {
        sum = static_cast<u8>(sum + p[i]);
    }
    return sum == 0;
}

void RegisterApic(u32 apic_id, u32 raw_domain)
{
    if (apic_id >= kMaxApicId)
    {
        // x2APIC ID overflows our 8-bit indexing table. Out-of-
        // scope for v0 — log once, fire the probe, skip.
        KLOG_WARN_V("acpi/srat", "apic_id >= kMaxApicId, skipping (x2APIC IDs >255 unsupported in v0)", apic_id);
        KBP_PROBE_V(::duetos::debug::ProbeId::kTopologyParseFailed, apic_id);
        return;
    }
    const u8 node = RemapDomain(raw_domain);
    if (node == kNoNode)
    {
        // Remap exhausted; leave the entry as kNoNode so callers
        // see "unknown node" and fall back to package-level
        // clustering.
        return;
    }
    g_apic_to_node[apic_id] = node;
}

void WalkRecords(const u8* base, u32 total_length)
{
    if (total_length <= kSratBodyOffset)
    {
        return; // No room for any affinity record.
    }
    const u8* cursor = base + kSratBodyOffset;
    const u8* end = base + total_length;
    while (cursor + 2 <= end)
    {
        const u8 type = cursor[0];
        const u8 len = cursor[1];
        if (len == 0 || cursor + len > end)
        {
            // Malformed record — fire the probe, stop walking.
            KBP_PROBE_V(::duetos::debug::ProbeId::kTopologyParseFailed,
                        static_cast<u64>(static_cast<uptr>(cursor - base)));
            return;
        }
        if (type == kSubtypeLapicAffinity && len == sizeof(LapicAffinity))
        {
            const auto* rec = reinterpret_cast<const LapicAffinity*>(cursor);
            if ((rec->flags & kAffinityFlagEnabled) != 0)
            {
                const u32 raw_domain =
                    static_cast<u32>(rec->proximity_low) | (static_cast<u32>(rec->proximity_high[0]) << 8) |
                    (static_cast<u32>(rec->proximity_high[1]) << 16) | (static_cast<u32>(rec->proximity_high[2]) << 24);
                RegisterApic(rec->apic_id, raw_domain);
            }
        }
        else if (type == kSubtypeX2ApicAffinity && len == sizeof(X2ApicAffinity))
        {
            const auto* rec = reinterpret_cast<const X2ApicAffinity*>(cursor);
            if ((rec->flags & kAffinityFlagEnabled) != 0)
            {
                RegisterApic(rec->x2apic_id, rec->proximity_domain);
            }
        }
        else if (type == kSubtypeMemoryAffinity && len == sizeof(MemoryAffinity))
        {
            const auto* rec = reinterpret_cast<const MemoryAffinity*>(cursor);
            if ((rec->flags & kAffinityFlagEnabled) != 0 && rec->length_bytes != 0 &&
                g_memory_range_count < kMaxMemoryRanges)
            {
                const u8 node = RemapDomain(rec->proximity_domain);
                if (node != kNoNode)
                {
                    auto& slot = g_memory_ranges[g_memory_range_count];
                    slot.base = rec->base_addr;
                    slot.length = rec->length_bytes;
                    slot.node = node;
                    slot.enabled = true;
                    ++g_memory_range_count;
                }
            }
        }
        // GICC / ITS / generic-initiator subtypes intentionally ignored.
        cursor += len;
    }
}

} // namespace

void SratInit(const void* srat_table)
{
    ResetState();
    g_inited = true;

    if (srat_table == nullptr)
    {
        // No SRAT in the system. UMA fallback handled by callers.
        return;
    }
    const auto* hdr = static_cast<const SdtPrefix*>(srat_table);
    if (hdr->signature[0] != 'S' || hdr->signature[1] != 'R' || hdr->signature[2] != 'A' || hdr->signature[3] != 'T')
    {
        KLOG_WARN("acpi/srat", "table at SRAT slot has wrong signature");
        KBP_PROBE_V(::duetos::debug::ProbeId::kTopologyParseFailed, 0);
        return;
    }
    if (hdr->length < kSratBodyOffset)
    {
        KLOG_WARN_V("acpi/srat", "SRAT length below minimum body offset", hdr->length);
        KBP_PROBE_V(::duetos::debug::ProbeId::kTopologyParseFailed, hdr->length);
        return;
    }
    if (!ChecksumOk(static_cast<const u8*>(srat_table), hdr->length))
    {
        // SRAT is optional and a bad checksum is firmware-level
        // corruption. Treat as absent rather than panicking — the
        // package-fallback path keeps the system running.
        KLOG_WARN("acpi/srat", "SRAT checksum failed, treating as absent");
        KBP_PROBE_V(::duetos::debug::ProbeId::kTopologyParseFailed, 0);
        return;
    }
    WalkRecords(static_cast<const u8*>(srat_table), hdr->length);
    g_present = (g_node_count > 0);
}

bool SratPresent()
{
    return g_present;
}

bool SratNodeForApic(u32 apic_id, u8* out_node)
{
    if (!g_inited || apic_id >= kMaxApicId)
    {
        return false;
    }
    const u8 node = g_apic_to_node[apic_id];
    if (node == kNoNode)
    {
        return false;
    }
    if (out_node != nullptr)
    {
        *out_node = node;
    }
    return true;
}

u8 SratNodeCount()
{
    return g_node_count;
}

u8 SratMemoryRangeCount()
{
    return g_memory_range_count;
}

bool SratMemoryRange(u8 idx, MemoryRange* out)
{
    if (idx >= g_memory_range_count || out == nullptr)
    {
        return false;
    }
    *out = g_memory_ranges[idx];
    return true;
}

} // namespace duetos::acpi::srat
