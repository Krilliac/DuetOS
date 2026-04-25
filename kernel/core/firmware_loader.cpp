#include "firmware_loader.h"

#include "../arch/x86_64/serial.h"
#include "klog.h"

namespace duetos::core
{

namespace
{

constinit FwBackendStats g_stats = {FwBackendKind::None, 0, 0, 0, 0};
constinit bool g_init_done = false;

} // namespace

void FwLoaderInit()
{
    if (g_init_done)
        return;
    g_init_done = true;
    g_stats.kind = FwBackendKind::None;
    arch::SerialWrite("[fw-loader] online — backend=None (no firmware-bearing FS mounted; FwLoad always misses).\n"
                      "[fw-loader] callers (iwlwifi / rtl88xx / bcm43xx / future) report `firmware_pending=true`.\n");
}

::duetos::core::Result<FwBlob> FwLoad(const FwLoadRequest& req)
{
    KLOG_TRACE_SCOPE("core/fw-loader", "FwLoad");
    ++g_stats.lookups;
    ++g_stats.misses;
    arch::SerialWrite("[fw-loader] miss vendor=\"");
    arch::SerialWrite(req.vendor != nullptr ? req.vendor : "?");
    arch::SerialWrite("\" basename=\"");
    arch::SerialWrite(req.basename != nullptr ? req.basename : "?");
    arch::SerialWrite("\"  (no backend installed)\n");
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

} // namespace duetos::core
