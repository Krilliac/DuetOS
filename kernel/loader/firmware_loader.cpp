#include "loader/firmware_loader.h"

#include "arch/x86_64/serial.h"
#include "fs/ramfs.h"
#include "fs/vfs.h"
#include "diag/cleanroom_trace.h"
#include "log/klog.h"

namespace duetos::core
{

namespace
{

constinit FwBackendStats g_stats = {FwBackendKind::None, FwSourcePolicy::OpenThenVendor, 0, 0, 0, 0};
constinit bool g_init_done = false;
constexpr u32 kFwPathMax = 160;
constinit FwTraceEntry g_trace[kFwTraceCapacity] = {};
constinit u32 g_trace_head = 0;  // next write slot
constinit u32 g_trace_count = 0; // number of valid entries

bool BuildFirmwarePathWithPrefix(char* out, u32 cap, const char* prefix, const char* vendor, const char* basename,
                                 bool with_vendor_prefix)
{
    if (out == nullptr || cap < 4 || prefix == nullptr || prefix[0] == '\0' || basename == nullptr ||
        basename[0] == '\0')
        return false;
    u32 idx = 0;
    for (u32 i = 0; prefix[i] != '\0'; ++i)
    {
        if (idx + 1 >= cap)
            return false;
        out[idx++] = prefix[i];
    }
    if (with_vendor_prefix)
    {
        if (vendor == nullptr || vendor[0] == '\0')
            return false;
        for (u32 i = 0; vendor[i] != '\0'; ++i)
        {
            if (idx + 1 >= cap)
                return false;
            out[idx++] = vendor[i];
        }
        if (idx + 2 >= cap)
            return false;
        out[idx++] = '/';
    }
    for (u32 i = 0; basename[i] != '\0'; ++i)
    {
        if (idx + 1 >= cap)
            return false;
        out[idx++] = basename[i];
    }
    out[idx] = '\0';
    return true;
}

void CopyBounded(char* dst, u32 dst_cap, const char* src)
{
    if (dst == nullptr || dst_cap == 0)
        return;
    u32 i = 0;
    if (src != nullptr)
    {
        for (; i + 1 < dst_cap && src[i] != '\0'; ++i)
            dst[i] = src[i];
    }
    dst[i] = '\0';
}

void TraceRecord(const char* vendor, const char* basename, const char* path, ErrorCode result, FwSourcePolicy policy)
{
    FwTraceEntry& e = g_trace[g_trace_head];
    CopyBounded(e.vendor, sizeof(e.vendor), vendor);
    CopyBounded(e.basename, sizeof(e.basename), basename);
    CopyBounded(e.attempted_path, sizeof(e.attempted_path), path);
    e.result = result;
    e.policy = policy;

    g_trace_head = (g_trace_head + 1) % kFwTraceCapacity;
    if (g_trace_count < kFwTraceCapacity)
        ++g_trace_count;
    CleanroomTraceRecord("fw-loader", "path-attempt", static_cast<u64>(result), static_cast<u64>(policy), 0);
}

bool BlobSizeAccepted(const FwLoadRequest& req, u64 bytes)
{
    if (bytes > 0xFFFFFFFFu)
        return false;
    if (req.min_bytes != 0 && bytes < req.min_bytes)
        return false;
    if (req.max_bytes != 0 && bytes > req.max_bytes)
        return false;
    return true;
}

} // namespace

void FwLoaderInit()
{
    if (g_init_done)
        return;
    g_init_done = true;
    g_stats.kind = FwBackendKind::Vfs;
    g_stats.policy = FwSourcePolicy::OpenThenVendor;
    arch::SerialWrite("[fw-loader] online — backend=VFS (/lib/firmware), policy=OpenThenVendor\n");
}

::duetos::core::Result<FwBlob> FwLoad(const FwLoadRequest& req)
{
    KLOG_TRACE_SCOPE("core/fw-loader", "FwLoad");
    if (req.basename == nullptr || req.basename[0] == '\0')
        return ::duetos::core::Err{ErrorCode::InvalidArgument};
    ++g_stats.lookups;
    char path[kFwPathMax] = {};

    auto try_one = [&](const char* prefix, bool with_vendor_prefix) -> ::duetos::core::Result<FwBlob>
    {
        if (!BuildFirmwarePathWithPrefix(path, sizeof(path), prefix, req.vendor, req.basename, with_vendor_prefix))
        {
            TraceRecord(req.vendor, req.basename, "<invalid-path>", ErrorCode::InvalidArgument, g_stats.policy);
            return ::duetos::core::Err{ErrorCode::InvalidArgument};
        }
        const fs::RamfsNode* n = fs::VfsLookup(fs::RamfsTrustedRoot(), path, sizeof(path));
        if (n == nullptr)
        {
            TraceRecord(req.vendor, req.basename, path, ErrorCode::NotFound, g_stats.policy);
            return ::duetos::core::Err{ErrorCode::NotFound};
        }
        if (n->type != fs::RamfsNodeType::kFile || n->file_bytes == nullptr)
        {
            TraceRecord(req.vendor, req.basename, path, ErrorCode::Corrupt, g_stats.policy);
            return ::duetos::core::Err{ErrorCode::Corrupt};
        }
        if (!BlobSizeAccepted(req, n->file_size))
        {
            TraceRecord(req.vendor, req.basename, path, ErrorCode::Corrupt, g_stats.policy);
            return ::duetos::core::Err{ErrorCode::Corrupt};
        }
        FwBlob blob{};
        blob.data = n->file_bytes;
        blob.size = static_cast<u32>(n->file_size);
        blob.verified = false;
        blob.handle = reinterpret_cast<u64>(n);
        TraceRecord(req.vendor, req.basename, path, ErrorCode::Ok, g_stats.policy);
        return blob;
    };

    auto try_and_log = [&](const char* prefix, bool with_vendor_prefix) -> ::duetos::core::Result<FwBlob>
    {
        auto r = try_one(prefix, with_vendor_prefix);
        if (r.has_value())
        {
            ++g_stats.hits;
            arch::SerialWrite("[fw-loader] hit ");
            arch::SerialWrite(path);
            arch::SerialWrite("\n");
            return r;
        }
        if (r.error() != ErrorCode::NotFound)
            return ::duetos::core::Err{r.error()};
        return ::duetos::core::Err{ErrorCode::NotFound};
    };

    if (g_stats.policy != FwSourcePolicy::VendorOnly)
    {
        // DuetOS-owned/open firmware namespaces. These are preferred so
        // deployments can sidestep vendor lock-in when open firmware is
        // available for the target chipset family.
        auto open_scoped = try_and_log("/lib/firmware/duetos/open/", /*with_vendor_prefix=*/true);
        if (open_scoped.has_value())
            return open_scoped;
        if (open_scoped.error() != ErrorCode::NotFound)
            return ::duetos::core::Err{open_scoped.error()};

        auto open_flat = try_and_log("/lib/firmware/duetos/open/", /*with_vendor_prefix=*/false);
        if (open_flat.has_value())
            return open_flat;
        if (open_flat.error() != ErrorCode::NotFound)
            return ::duetos::core::Err{open_flat.error()};
    }

    if (g_stats.policy != FwSourcePolicy::OpenOnly)
    {
        auto scoped = try_and_log("/lib/firmware/", /*with_vendor_prefix=*/true);
        if (scoped.has_value())
            return scoped;
        if (scoped.error() != ErrorCode::NotFound)
            return ::duetos::core::Err{scoped.error()};

        auto flat = try_and_log("/lib/firmware/", /*with_vendor_prefix=*/false);
        if (flat.has_value())
            return flat;
        if (flat.error() != ErrorCode::NotFound)
            return ::duetos::core::Err{flat.error()};
    }

    ++g_stats.misses;
    arch::SerialWrite("[fw-loader] miss vendor=\"");
    arch::SerialWrite(req.vendor != nullptr ? req.vendor : "?");
    arch::SerialWrite("\" basename=\"");
    arch::SerialWrite(req.basename);
    arch::SerialWrite("\"\n");
    return ::duetos::core::Err{ErrorCode::NotFound};
}

void FwRelease(const FwBlob& blob)
{
    // No-op until the backend allocates anything.
    (void)blob;
}

FwBackendStats FwBackendStatsRead()
{
    return g_stats;
}

void FwSetSourcePolicy(FwSourcePolicy policy)
{
    g_stats.policy = policy;
}

FwSourcePolicy FwSourcePolicyRead()
{
    return g_stats.policy;
}

u32 FwTraceCount()
{
    return g_trace_count;
}

bool FwTraceRead(u32 index, FwTraceEntry* out)
{
    if (out == nullptr || index >= g_trace_count)
        return false;
    const u32 oldest = (g_trace_head + kFwTraceCapacity - g_trace_count) % kFwTraceCapacity;
    const u32 slot = (oldest + index) % kFwTraceCapacity;
    *out = g_trace[slot];
    return true;
}

void FwTraceClear()
{
    g_trace_head = 0;
    g_trace_count = 0;
    for (u32 i = 0; i < kFwTraceCapacity; ++i)
        g_trace[i] = {};
}

} // namespace duetos::core
