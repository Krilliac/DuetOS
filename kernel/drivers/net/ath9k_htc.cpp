#include "drivers/net/ath9k_htc.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "drivers/usb/xhci.h"
#include "loader/firmware_loader.h"
#include "log/klog.h"
#include "net/wireless/wifi_diag.h"

namespace duetos::drivers::net
{

namespace
{

namespace diag = duetos::net::wireless::diag;

// USB VID/PID match table. AR9271 single-chip devices use Atheros
// VID 0x0CF3 plus a handful of OEM rebrands; AR7010-based USB
// adapters share VID 0x0CF3 across product IDs 0x7010 / 0x7015.
// Numeric IDs are hardware ABI documented in
// `qca/open-ath9k-htc-firmware/target_firmware/...` and the Linux
// ath9k_htc USB device table; only the IDs themselves are copied.
constexpr AthHtcUsbId kAthHtcUsbIds[] = {
    // AR9271 (htc_9271.fw)
    {0x0CF3, 0x9271, AthHtcTarget::Ar9271, "Atheros AR9271 reference"},
    {0x0CF3, 0x1006, AthHtcTarget::Ar9271, "Atheros AR9271 OEM"},
    {0x0CF3, 0xB003, AthHtcTarget::Ar9271, "Ubiquiti SR71-USB AR9271"},
    {0x0CF3, 0x7015, AthHtcTarget::Ar7010, "Atheros AR7010 v1.1"},
    {0x0CF3, 0x7010, AthHtcTarget::Ar7010, "Atheros AR7010 reference"},
    {0x0846, 0x9030, AthHtcTarget::Ar9271, "Netgear WNA1100"},
    {0x07D1, 0x3A10, AthHtcTarget::Ar9271, "D-Link DWA-126"},
    {0x13D3, 0x3327, AthHtcTarget::Ar9271, "AzureWave AW-NU253"},
    {0x040D, 0x3801, AthHtcTarget::Ar9271, "VIA VNT-6656"},
    {0x83AD, 0x7240, AthHtcTarget::Ar9271, "TP-Link TL-WN722N v1"},
};
constexpr u32 kAthHtcUsbIdCount = sizeof(kAthHtcUsbIds) / sizeof(kAthHtcUsbIds[0]);

constinit AthHtcStats g_stats = {};
constinit AthHtcAdapter g_adapters[kAthHtcMaxAdapters] = {};
constinit u32 g_adapter_count = 0;
constinit bool g_init_done = false;

const AthHtcUsbId* FindUsbIdSlow(u16 vendor_id, u16 product_id)
{
    for (u32 i = 0; i < kAthHtcUsbIdCount; ++i)
    {
        if (kAthHtcUsbIds[i].vendor_id == vendor_id && kAthHtcUsbIds[i].product_id == product_id)
            return &kAthHtcUsbIds[i];
    }
    return nullptr;
}

// Build a request basename per chip family. The open firmware files
// in `qca/open-ath9k-htc-firmware` and `linux-firmware/ath9k_htc/`
// are exactly `htc_9271.fw` / `htc_7010.fw`. The firmware loader's
// `OpenThenVendor` policy will check `/lib/firmware/duetos/open/`
// first (where the source-rebuilt package lives) before the legacy
// vendor namespace.
const char* BasenameForTarget(AthHtcTarget target)
{
    switch (target)
    {
    case AthHtcTarget::Ar9271:
        return "htc_9271.fw";
    case AthHtcTarget::Ar7010:
        return "htc_7010.fw";
    case AthHtcTarget::Unknown:
    default:
        return nullptr;
    }
}

void LogBringUpHeader(const AthHtcUsbId& match, u8 slot_id)
{
    arch::SerialWrite("[ath9k-htc] match slot=");
    arch::SerialWriteHex(slot_id);
    arch::SerialWrite(" vid=");
    arch::SerialWriteHex(match.vendor_id);
    arch::SerialWrite(" pid=");
    arch::SerialWriteHex(match.product_id);
    arch::SerialWrite(" target=");
    arch::SerialWrite(AthHtcTargetName(match.target));
    arch::SerialWrite(" (");
    arch::SerialWrite(match.tag);
    arch::SerialWrite(")\n");
}

bool BringUpSlot(const AthHtcUsbId& match, u8 slot_id, AthHtcAdapter& adapter)
{
    adapter.in_use = true;
    adapter.slot_id = slot_id;
    adapter.vendor_id = match.vendor_id;
    adapter.product_id = match.product_id;
    adapter.target = match.target;
    adapter.tag = match.tag;
    ++g_stats.adapters_seen;
    diag::RecordOk(diag::Layer::Driver, "ath-match", slot_id, match.vendor_id, match.product_id, match.tag);

    const char* basename = BasenameForTarget(match.target);
    if (basename == nullptr)
    {
        diag::RecordErr(diag::Layer::Driver, "ath-target-unknown",
                        static_cast<u32>(::duetos::core::ErrorCode::InvalidArgument), slot_id, 0, 0);
        return false;
    }

    duetos::core::FwLoadRequest req{};
    req.vendor = "ath9k-htc";
    req.basename = basename;
    req.min_bytes = kAthHtcMinBytes;
    req.max_bytes = kAthHtcMaxBytes;
    auto fw = duetos::core::FwLoad(req);
    if (!fw.has_value())
    {
        if (fw.error() == ::duetos::core::ErrorCode::NotFound)
            ++g_stats.firmware_missing;
        else
            ++g_stats.firmware_corrupt;
        arch::SerialWrite("[ath9k-htc] firmware miss (");
        arch::SerialWrite(basename);
        arch::SerialWrite(") — adapter staged without bytes\n");
        diag::RecordErr(diag::Layer::Driver, "ath-fw-miss", static_cast<u32>(fw.error()), slot_id, 0, 0);
        return false;
    }
    adapter.firmware_loaded = true;

    AthHtcFirmwareParsed parsed{};
    auto pr = AthHtcFirmwareParse(fw.value().data, fw.value().size, &parsed);
    if (!pr.has_value() || !parsed.valid)
    {
        ++g_stats.firmware_corrupt;
        duetos::core::FwRelease(fw.value());
        diag::RecordErr(diag::Layer::Driver, "ath-fw-parse", static_cast<u32>(::duetos::core::ErrorCode::Corrupt),
                        slot_id, fw.value().size, 0);
        return false;
    }
    AthHtcFirmwareLog(parsed);
    adapter.firmware_parsed = true;
    adapter.last_load_address = parsed.load_address;
    adapter.firmware_fletcher32 = parsed.fletcher32;
    ++g_stats.firmware_ready;

    AthHtcUploadPlan plan{};
    auto br = AthHtcBuildUploadPlan(parsed, &plan);
    if (!br.has_value())
    {
        duetos::core::FwRelease(fw.value());
        diag::RecordErr(diag::Layer::Driver, "ath-plan-fail", static_cast<u32>(br.error()), slot_id, 0, 0);
        return false;
    }
    adapter.last_chunks_planned = plan.chunk_count;

    AthHtcUploadResult ur{};
    ++g_stats.uploads_attempted;
    auto up = AthHtcUploadDrive(slot_id, fw.value().data, fw.value().size, plan, &ur);
    adapter.last_chunks_sent = ur.chunks_sent;
    adapter.last_bytes_sent = ur.bytes_sent;
    duetos::core::FwRelease(fw.value());
    if (!up.has_value() || !ur.ok)
    {
        // Firmware upload bailed mid-way — the stage name lives in
        // the existing serial dump; klog gets the failed-stage enum
        // value so a panic dump replay can identify which upload
        // phase the device rejected.
        KLOG_ERROR_2V("drivers/net/ath9k_htc", "firmware upload failed", "stage", static_cast<u64>(ur.failed_at),
                      "chunks_sent", static_cast<u64>(ur.chunks_sent));
        arch::SerialWrite("[ath9k-htc] upload failed at stage=");
        arch::SerialWrite(AthHtcUploadStageName(ur.failed_at));
        arch::SerialWrite(" sent=");
        arch::SerialWriteHex(ur.chunks_sent);
        arch::SerialWrite("/");
        arch::SerialWriteHex(ur.chunks_planned);
        arch::SerialWrite("\n");
        return false;
    }
    adapter.firmware_uploaded = true;
    ++g_stats.uploads_succeeded;
    arch::SerialWrite("[ath9k-htc] firmware online slot=");
    arch::SerialWriteHex(slot_id);
    arch::SerialWrite(" bytes=");
    arch::SerialWriteHex(ur.bytes_sent);
    arch::SerialWrite(" chunks=");
    arch::SerialWriteHex(ur.chunks_sent);
    arch::SerialWrite("\n");
    return true;
}

void ScanPortRecords()
{
    const u32 controllers = drivers::usb::xhci::XhciCount();
    for (u32 ci = 0; ci < controllers; ++ci)
    {
        const drivers::usb::xhci::ControllerInfo* c = drivers::usb::xhci::XhciControllerAt(ci);
        if (c == nullptr)
            continue;
        for (u32 pi = 0; pi < drivers::usb::xhci::kMaxXhciPortsPerController; ++pi)
        {
            const drivers::usb::xhci::PortRecord& p = c->ports[pi];
            if (!p.slot_ok || !p.descriptor_ok || p.slot_id == 0)
                continue;
            const AthHtcUsbId* match = FindUsbIdSlow(p.vendor_id, p.product_id);
            if (match == nullptr)
                continue;
            if (g_adapter_count >= kAthHtcMaxAdapters)
            {
                arch::SerialWrite("[ath9k-htc] adapter table full — skipping further matches\n");
                return;
            }
            LogBringUpHeader(*match, p.slot_id);
            AthHtcAdapter& adapter = g_adapters[g_adapter_count++];
            BringUpSlot(*match, p.slot_id, adapter);
        }
    }
}

} // namespace

const AthHtcUsbId* AthHtcMatchUsbId(u16 vendor_id, u16 product_id)
{
    return FindUsbIdSlow(vendor_id, product_id);
}

u32 AthHtcUsbIdCount()
{
    return kAthHtcUsbIdCount;
}

const AthHtcUsbId& AthHtcUsbIdAt(u32 i)
{
    KASSERT_WITH_VALUE(i < kAthHtcUsbIdCount, "drivers/net/ath9k_htc", "AthHtcUsbIdAt index out of range", i);
    return kAthHtcUsbIds[i];
}

void AthHtcInit()
{
    KLOG_TRACE_SCOPE("drivers/net/ath9k_htc", "Init");
    if (g_init_done)
        return;
    g_init_done = true;
    arch::SerialWrite("[ath9k-htc] scanning xHCI ports for AR9271/AR7010 adapters\n");
    ScanPortRecords();
    arch::SerialWrite("[ath9k-htc] init done — adapters=");
    arch::SerialWriteHex(g_adapter_count);
    arch::SerialWrite(" fw_ready=");
    arch::SerialWriteHex(g_stats.firmware_ready);
    arch::SerialWrite(" uploaded=");
    arch::SerialWriteHex(g_stats.uploads_succeeded);
    arch::SerialWrite("\n");
}

AthHtcStats AthHtcStatsRead()
{
    return g_stats;
}

u32 AthHtcAdapterCount()
{
    return g_adapter_count;
}

const AthHtcAdapter& AthHtcAdapterAt(u32 index)
{
    KASSERT_WITH_VALUE(index < g_adapter_count, "drivers/net/ath9k_htc", "AthHtcAdapterAt index out of range", index);
    return g_adapters[index];
}

void AthHtcSelfTest()
{
    // VID/PID match table sanity. The two canonical reference IDs
    // (AR9271 0x9271, AR7010 0x7010) must be present and map to
    // the right target.
    const AthHtcUsbId* m9271 = AthHtcMatchUsbId(0x0CF3, 0x9271);
    KASSERT(m9271 != nullptr && m9271->target == AthHtcTarget::Ar9271, "drivers/net/ath9k_htc",
            "AR9271 0x0CF3:0x9271 should match");

    const AthHtcUsbId* m7010 = AthHtcMatchUsbId(0x0CF3, 0x7010);
    KASSERT(m7010 != nullptr && m7010->target == AthHtcTarget::Ar7010, "drivers/net/ath9k_htc",
            "AR7010 0x0CF3:0x7010 should match");

    const AthHtcUsbId* tplink = AthHtcMatchUsbId(0x83AD, 0x7240);
    KASSERT(tplink != nullptr && tplink->target == AthHtcTarget::Ar9271, "drivers/net/ath9k_htc",
            "TP-Link TL-WN722N v1 should match AR9271");

    KASSERT(AthHtcMatchUsbId(0xDEAD, 0xBEEF) == nullptr, "drivers/net/ath9k_htc", "unknown VID/PID must not match");
    KASSERT(AthHtcUsbIdCount() == kAthHtcUsbIdCount, "drivers/net/ath9k_htc", "match table count drifted");

    // BasenameForTarget should hand back the canonical open
    // firmware filenames; AthHtcTarget::Unknown must yield null.
    // Re-derive via the same dispatch the bring-up uses.
    KASSERT(BasenameForTarget(AthHtcTarget::Ar9271) != nullptr, "drivers/net/ath9k_htc",
            "AR9271 basename must be non-null");
    KASSERT(BasenameForTarget(AthHtcTarget::Ar7010) != nullptr, "drivers/net/ath9k_htc",
            "AR7010 basename must be non-null");
    KASSERT(BasenameForTarget(AthHtcTarget::Unknown) == nullptr, "drivers/net/ath9k_htc",
            "Unknown target basename must be null");

    arch::SerialWrite("[ath9k-htc] selftest pass\n");
}

} // namespace duetos::drivers::net
