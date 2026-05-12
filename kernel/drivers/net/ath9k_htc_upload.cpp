#include "drivers/net/ath9k_htc_upload.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "drivers/usb/xhci.h"
#include "log/klog.h"
#include "net/wireless/wifi_diag.h"

namespace duetos::drivers::net
{

namespace
{

namespace diag = duetos::net::wireless::diag;

u32 WvalueForAddress(u32 addr)
{
    // Linux hif_usb encodes the byte address into wValue by
    // shifting right 8: the bootrom recovers `addr & ~0xFF` by
    // shifting wValue back left 8. The low 8 bits of `addr` are
    // therefore always zero on the wire. Our chunk sizes are 4 KiB
    // and load addresses are page-aligned, so this is exact for
    // every plan we generate.
    return (addr >> 8) & 0xFFFFu;
}

} // namespace

const char* AthHtcUploadStageName(AthHtcUploadStage s)
{
    switch (s)
    {
    case AthHtcUploadStage::Idle:
        return "idle";
    case AthHtcUploadStage::PlanReady:
        return "plan-ready";
    case AthHtcUploadStage::StreamingChunks:
        return "streaming-chunks";
    case AthHtcUploadStage::SendingComplete:
        return "sending-complete";
    case AthHtcUploadStage::Complete:
        return "complete";
    case AthHtcUploadStage::Failed:
        return "failed";
    }
    return "?";
}

::duetos::core::Result<void> AthHtcBuildUploadPlan(const AthHtcFirmwareParsed& parsed, AthHtcUploadPlan* plan)
{
    if (plan == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    *plan = {};
    if (!parsed.valid || parsed.declared_size == 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
    if (parsed.chunk_count == 0 || parsed.chunk_count > kAthHtcMaxPlanChunks)
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
    if (parsed.load_address == 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};

    plan->target = parsed.target;
    plan->load_address = parsed.load_address;
    plan->chunk_count = parsed.chunk_count;
    plan->finalize_wvalue = WvalueForAddress(parsed.load_address);

    u32 remaining = parsed.declared_size;
    u32 offset = 0;
    for (u32 i = 0; i < parsed.chunk_count; ++i)
    {
        const u32 len = (remaining > kAthHtcDownloadChunkBytes) ? kAthHtcDownloadChunkBytes : remaining;
        plan->chunks[i].offset = offset;
        plan->chunks[i].length = len;
        plan->chunks[i].wvalue = WvalueForAddress(parsed.load_address + offset);
        offset += len;
        remaining -= len;
    }
    if (remaining != 0 || offset != parsed.declared_size)
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
    return ::duetos::core::Result<void>{};
}

::duetos::core::Result<void> AthHtcUploadDrive(u8 slot_id, const u8* blob, u32 blob_size, const AthHtcUploadPlan& plan,
                                               AthHtcUploadResult* result)
{
    KLOG_TRACE_SCOPE("drivers/net/ath9k_htc", "UploadDrive");
    AthHtcUploadResult tmp{};
    AthHtcUploadResult& r = (result != nullptr) ? *result : tmp;
    r = {};
    r.failed_at = AthHtcUploadStage::Idle;
    r.chunks_planned = plan.chunk_count;
    diag::RecordOk(diag::Layer::FwUpload, "ath-plan-ready", slot_id, plan.chunk_count, plan.load_address, "ath9k_htc");

    if (slot_id == 0 || blob == nullptr || blob_size == 0)
    {
        r.failed_at = AthHtcUploadStage::PlanReady;
        diag::RecordErr(diag::Layer::FwUpload, "ath-bad-args",
                        static_cast<u32>(::duetos::core::ErrorCode::InvalidArgument), slot_id, 0, 0);
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }
    if (plan.chunk_count == 0 || plan.chunk_count > kAthHtcMaxPlanChunks)
    {
        r.failed_at = AthHtcUploadStage::PlanReady;
        diag::RecordErr(diag::Layer::FwUpload, "ath-bad-plan", static_cast<u32>(::duetos::core::ErrorCode::Corrupt),
                        plan.chunk_count, 0, 0);
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
    }

    r.failed_at = AthHtcUploadStage::StreamingChunks;
    for (u32 i = 0; i < plan.chunk_count; ++i)
    {
        const AthHtcChunkPlan& c = plan.chunks[i];
        if (c.offset + c.length > blob_size)
        {
            diag::RecordErr(diag::Layer::FwUpload, "ath-oob-chunk",
                            static_cast<u32>(::duetos::core::ErrorCode::Corrupt), i, c.offset, c.length);
            return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
        }
        const bool ok = drivers::usb::xhci::XhciControlOut(slot_id, kAthHtcVendorOutDevice, kAthHtcReqFirmwareDownload,
                                                           static_cast<u16>(c.wvalue), /*wIndex=*/0, blob + c.offset,
                                                           static_cast<u16>(c.length));
        r.last_chunk_bytes = c.length;
        r.last_wvalue = c.wvalue;
        if (!ok)
        {
            diag::RecordErr(diag::Layer::FwUpload, "ath-chunk-fail",
                            static_cast<u32>(::duetos::core::ErrorCode::IoError), i, c.wvalue, c.length);
            return ::duetos::core::Err{::duetos::core::ErrorCode::IoError};
        }
        ++r.chunks_sent;
        r.bytes_sent += c.length;
    }

    r.failed_at = AthHtcUploadStage::SendingComplete;
    const bool fin_ok =
        drivers::usb::xhci::XhciControlOut(slot_id, kAthHtcVendorOutDevice, kAthHtcReqFirmwareDownloadComplete,
                                           static_cast<u16>(plan.finalize_wvalue), /*wIndex=*/0,
                                           /*buf=*/nullptr, /*len=*/0);
    if (!fin_ok)
    {
        diag::RecordErr(diag::Layer::FwUpload, "ath-finalize-fail",
                        static_cast<u32>(::duetos::core::ErrorCode::IoError), slot_id, plan.finalize_wvalue, 0);
        return ::duetos::core::Err{::duetos::core::ErrorCode::IoError};
    }
    r.failed_at = AthHtcUploadStage::Complete;
    r.ok = true;
    diag::RecordOk(diag::Layer::FwUpload, "ath-upload-ok", slot_id, r.chunks_sent, r.bytes_sent, "ath9k_htc");
    return ::duetos::core::Result<void>{};
}

void AthHtcUploadSelfTest()
{
    // Build a plan for a synthetic 51 KiB AR9271 blob and verify
    // every chunk's offset, length, and wValue. Plan construction
    // is pure-function — we don't need an xHCI device to test it.
    constexpr u32 kSize = 51u * 1024;
    static u8 buf[kSize];
    for (u32 i = 0; i < kSize; ++i)
        buf[i] = static_cast<u8>((i + 0x10u) & 0xFFu);

    AthHtcFirmwareParsed parsed{};
    KASSERT(AthHtcFirmwareParse(buf, kSize, &parsed).has_value(), "drivers/net/ath9k_htc_upload",
            "synthetic AR9271 parse should succeed");

    AthHtcUploadPlan plan{};
    auto br = AthHtcBuildUploadPlan(parsed, &plan);
    KASSERT(br.has_value(), "drivers/net/ath9k_htc_upload", "plan build should succeed");
    KASSERT(plan.target == AthHtcTarget::Ar9271, "drivers/net/ath9k_htc_upload", "plan target wrong");
    KASSERT(plan.load_address == kAthHtcLoadAddrAr9271, "drivers/net/ath9k_htc_upload", "plan load addr wrong");
    KASSERT(plan.chunk_count == 13u, "drivers/net/ath9k_htc_upload", "plan chunk_count wrong");

    u32 acc = 0;
    for (u32 i = 0; i < plan.chunk_count; ++i)
    {
        KASSERT(plan.chunks[i].offset == acc, "drivers/net/ath9k_htc_upload", "plan offset wrong");
        const u32 expect = (i == plan.chunk_count - 1) ? (kSize - acc) : kAthHtcDownloadChunkBytes;
        KASSERT(plan.chunks[i].length == expect, "drivers/net/ath9k_htc_upload", "plan length wrong");
        const u32 expect_wval = ((kAthHtcLoadAddrAr9271 + acc) >> 8) & 0xFFFFu;
        KASSERT(plan.chunks[i].wvalue == expect_wval, "drivers/net/ath9k_htc_upload", "plan wvalue wrong");
        acc += plan.chunks[i].length;
    }
    KASSERT(acc == kSize, "drivers/net/ath9k_htc_upload", "plan total bytes mismatch");
    KASSERT(plan.finalize_wvalue == ((kAthHtcLoadAddrAr9271 >> 8) & 0xFFFFu), "drivers/net/ath9k_htc_upload",
            "plan finalize wvalue wrong");

    // Drive() with slot_id=0 must reject without touching xHCI.
    AthHtcUploadResult result{};
    auto bad = AthHtcUploadDrive(/*slot_id=*/0, buf, kSize, plan, &result);
    KASSERT(!bad.has_value() && bad.error() == ::duetos::core::ErrorCode::InvalidArgument,
            "drivers/net/ath9k_htc_upload", "drive with slot=0 should reject");
    KASSERT(result.failed_at == AthHtcUploadStage::PlanReady, "drivers/net/ath9k_htc_upload",
            "drive should stop at PlanReady on bad args");

    // Invalid parsed (valid=false) plan build must reject.
    {
        AthHtcFirmwareParsed not_valid{};
        AthHtcUploadPlan p{};
        auto b = AthHtcBuildUploadPlan(not_valid, &p);
        KASSERT(!b.has_value() && b.error() == ::duetos::core::ErrorCode::Corrupt, "drivers/net/ath9k_htc_upload",
                "invalid parsed should fail to plan");
    }

    arch::SerialWrite("[ath9k-htc-upload] selftest pass\n");
}

} // namespace duetos::drivers::net
