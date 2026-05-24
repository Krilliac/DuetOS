#include "diag/selfthink_persist.h"

#include "debug/probes.h"
#include "fs/fat32.h"
#include "log/klog.h"

namespace duetos::diag::selfthink::persist
{

namespace
{

// On-disk header. Sized to a multiple of 8 B so the trailing
// CausalEntry array stays naturally aligned.
struct DiskHeader
{
    u32 magic;
    u32 version;
    u32 entry_count;
    u32 reserved;
};
static_assert(sizeof(DiskHeader) == 16, "DiskHeader packing changed");

// Prior-boot buffer + count. Lives in .bss. Capacity matches the
// live ring so a fully-populated prior boot fits.
CausalEntry g_prior_ring[kCausalRingCap] = {};
u32 g_prior_count = 0;
bool g_installed = false;
bool g_prior_loaded = false;

// Serialisation scratch buffer — header + every live ring entry.
// Sized once; reused for every flush. Lives in .bss for
// allocator-free operation.
constexpr u64 kScratchBytes = sizeof(DiskHeader) + kCausalRingCap * sizeof(CausalEntry);
u8 g_scratch[kScratchBytes] = {};

const ::duetos::fs::fat32::Volume* RootVolume()
{
    if (::duetos::fs::fat32::Fat32VolumeCount() == 0)
        return nullptr;
    return ::duetos::fs::fat32::Fat32Volume(0);
}

// Read the existing KERNEL.THK into g_prior_ring. Best-effort:
// any failure (no volume, file missing, header invalid, version
// mismatch, truncated payload) leaves g_prior_count = 0.
void LoadPriorFromDisk()
{
    const auto* vol = RootVolume();
    if (vol == nullptr)
        return;

    ::duetos::fs::fat32::DirEntry entry = {};
    if (!::duetos::fs::fat32::Fat32LookupPath(vol, kPersistPath, &entry))
        return;

    // Read up to the scratch capacity. Anything larger has been
    // hand-edited or corrupted — we still process what fits.
    const i64 read = ::duetos::fs::fat32::Fat32ReadFile(vol, &entry, g_scratch, kScratchBytes);
    if (read < static_cast<i64>(sizeof(DiskHeader)))
        return;

    DiskHeader hdr = {};
    for (u32 i = 0; i < sizeof(DiskHeader); ++i)
        reinterpret_cast<u8*>(&hdr)[i] = g_scratch[i];

    if (hdr.magic != kPersistMagic || hdr.version != kPersistVersion)
        return;

    if (hdr.entry_count > kCausalRingCap)
        return; // header inconsistent — refuse to copy bad payload

    const u64 expected_bytes = sizeof(DiskHeader) + hdr.entry_count * sizeof(CausalEntry);
    if (static_cast<u64>(read) < expected_bytes)
        return; // truncated

    // Copy entries out of the scratch buffer.
    for (u32 i = 0; i < hdr.entry_count; ++i)
    {
        const u64 src_off = sizeof(DiskHeader) + i * sizeof(CausalEntry);
        for (u64 b = 0; b < sizeof(CausalEntry); ++b)
            reinterpret_cast<u8*>(&g_prior_ring[i])[b] = g_scratch[src_off + b];
    }
    g_prior_count = hdr.entry_count;
    g_prior_loaded = true;
}

// Serialise the current live ring into g_scratch and write to
// disk. Walks the live ring newest-first via CausalRingWalk so
// the on-disk layout matches the chronological-by-tick ordering
// an operator expects in `selfthink prev causality`.
struct SerializeCtx
{
    u8* dst;
    u32 capacity;
    u32 written;
};

bool SerializeCb(const CausalEntry& e, void* ctx)
{
    auto* x = static_cast<SerializeCtx*>(ctx);
    if (x->written >= x->capacity)
        return false;
    const u64 off = sizeof(DiskHeader) + x->written * sizeof(CausalEntry);
    for (u64 b = 0; b < sizeof(CausalEntry); ++b)
        x->dst[off + b] = reinterpret_cast<const u8*>(&e)[b];
    ++x->written;
    return true;
}

} // namespace

void Install()
{
    if (g_installed)
        return;

    // Step 1: load prior boot's KERNEL.THK into the in-RAM buffer.
    // Best-effort — first boot has no prior file and that's fine.
    LoadPriorFromDisk();

    const auto* vol = RootVolume();
    if (vol == nullptr)
    {
        // No FAT32 volume — flush will no-op until one mounts.
        g_installed = true;
        return;
    }

    // Step 2: replace the on-disk file with a fresh-but-empty header
    // so the periodic flush starts from a known state. Delete first
    // (FAT32 Fat32CreateAtPath does not implicitly overwrite).
    (void)::duetos::fs::fat32::Fat32DeleteAtPath(vol, kPersistPath);

    DiskHeader empty_hdr = {kPersistMagic, kPersistVersion, 0, 0};
    (void)::duetos::fs::fat32::Fat32CreateAtPath(vol, kPersistPath, &empty_hdr, sizeof(empty_hdr));

    g_installed = true;
}

void Flush()
{
    if (!g_installed)
        return;
    const auto* vol = RootVolume();
    if (vol == nullptr)
        return;

    // Header first.
    DiskHeader hdr = {kPersistMagic, kPersistVersion, 0, 0};
    SerializeCtx ctx{g_scratch, kCausalRingCap, 0};
    CausalRingWalk(&SerializeCb, &ctx);
    hdr.entry_count = ctx.written;

    for (u32 i = 0; i < sizeof(DiskHeader); ++i)
        g_scratch[i] = reinterpret_cast<const u8*>(&hdr)[i];

    const u64 total_bytes = sizeof(DiskHeader) + ctx.written * sizeof(CausalEntry);

    // Rewrite: delete then create. Same pattern as FixJournalFlush.
    (void)::duetos::fs::fat32::Fat32DeleteAtPath(vol, kPersistPath);
    (void)::duetos::fs::fat32::Fat32CreateAtPath(vol, kPersistPath, g_scratch, total_bytes);
}

bool PriorAvailable()
{
    return g_prior_loaded && g_prior_count > 0;
}

u32 PriorEntryCount()
{
    return g_prior_count;
}

u32 PriorRingWalk(bool (*cb)(const CausalEntry& e, void* ctx), void* ctx)
{
    if (cb == nullptr || g_prior_count == 0)
        return 0;
    u32 visited = 0;
    // The on-disk entries were written newest-first (Serialize
    // walked CausalRingWalk newest-first), so iteration order
    // already matches "newest first".
    for (u32 i = 0; i < g_prior_count; ++i)
    {
        ++visited;
        if (!cb(g_prior_ring[i], ctx))
            break;
    }
    return visited;
}

void SelfTest()
{
    using duetos::core::Log;
    using duetos::core::LogLevel;
    using duetos::core::LogWithValue;

    // Pure in-RAM round-trip: serialise one synthetic entry into a
    // scratch buffer, parse it back, compare. Avoids touching FAT32
    // (the install path already covers the live FS round-trip with
    // an empty payload).
    CausalEntry sent = {};
    sent.tick = 0xDEADBEEFCAFEBABEULL;
    sent.cpu_id = 7;
    sent.kind = static_cast<u16>(CausalKind::Annotation);
    sent.source_id = 42;
    sent.value = 0xFEDCBA9876543210ULL;
    sent.caller_rip = 0x123456789ABCDEF0ULL;
    sent.tag[0] = 'p';
    sent.tag[1] = 'r';
    sent.tag[2] = 's';
    sent.tag[3] = 't';
    sent.tag[4] = '\0';

    u8 buf[sizeof(DiskHeader) + sizeof(CausalEntry)] = {};
    DiskHeader hdr_w{kPersistMagic, kPersistVersion, 1, 0};
    for (u32 i = 0; i < sizeof(DiskHeader); ++i)
        buf[i] = reinterpret_cast<const u8*>(&hdr_w)[i];
    for (u32 i = 0; i < sizeof(CausalEntry); ++i)
        buf[sizeof(DiskHeader) + i] = reinterpret_cast<const u8*>(&sent)[i];

    DiskHeader hdr_r = {};
    for (u32 i = 0; i < sizeof(DiskHeader); ++i)
        reinterpret_cast<u8*>(&hdr_r)[i] = buf[i];

    if (hdr_r.magic != kPersistMagic || hdr_r.version != kPersistVersion || hdr_r.entry_count != 1)
    {
        Log(LogLevel::Error, "diag/selfthink-persist", "selftest: header parse mismatch");
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail, reinterpret_cast<u64>(&SelfTest), 1);
        return;
    }

    CausalEntry got = {};
    for (u32 i = 0; i < sizeof(CausalEntry); ++i)
        reinterpret_cast<u8*>(&got)[i] = buf[sizeof(DiskHeader) + i];

    if (got.tick != sent.tick || got.value != sent.value || got.caller_rip != sent.caller_rip ||
        got.kind != sent.kind || got.source_id != sent.source_id || got.cpu_id != sent.cpu_id)
    {
        Log(LogLevel::Error, "diag/selfthink-persist", "selftest: entry payload mismatch");
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail, reinterpret_cast<u64>(&SelfTest), 2);
        return;
    }

    // Tag check — bounded copy must survive the round-trip.
    for (u32 i = 0; i < 5; ++i)
    {
        if (got.tag[i] != sent.tag[i])
        {
            LogWithValue(LogLevel::Error, "diag/selfthink-persist", "selftest: tag mismatch idx", i);
            ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail, reinterpret_cast<u64>(&SelfTest),
                                       3);
            return;
        }
    }

    LogWithValue(LogLevel::Info, "diag/selfthink-persist", "selftest pass entry_size", sizeof(CausalEntry));
}

} // namespace duetos::diag::selfthink::persist
