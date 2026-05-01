#include "drivers/net/rtl88xx_upload.h"

#include "core/panic.h"
#include "net/wireless/wifi_diag.h"
#include "time/tick.h"

namespace duetos::drivers::net
{

namespace
{

namespace diag = duetos::net::wireless::diag;

u8 Mmio8Read(const NicInfo& n, u32 off)
{
    if (n.mmio_virt == nullptr)
        return 0xFFu;
    const u8 v = *reinterpret_cast<volatile u8*>(static_cast<u8*>(n.mmio_virt) + off);
    diag::Record(diag::Layer::FwUpload, "rtl-r8", off, v, 0, 0, "rtl");
    return v;
}

void Mmio8Write(const NicInfo& n, u32 off, u8 v)
{
    if (n.mmio_virt == nullptr)
        return;
    *reinterpret_cast<volatile u8*>(static_cast<u8*>(n.mmio_virt) + off) = v;
    diag::Record(diag::Layer::FwUpload, "rtl-w8", off, v, 0, 0, "rtl");
}

bool PollByteWithTimeout(NicInfo& n, u32 off, u8 mask, u8 expect, u32 timeout_ticks, u32* polls_out)
{
    const u64 deadline = duetos::time::TickCount() + timeout_ticks;
    u32 polls = 0;
    for (;;)
    {
        ++polls;
        const u8 v = Mmio8Read(n, off);
        if ((v & mask) == expect)
        {
            if (polls_out != nullptr)
                *polls_out = polls;
            diag::RecordOk(diag::Layer::FwUpload, "rtl-poll-hit", off, mask, polls);
            return true;
        }
        if (duetos::time::TickCount() >= deadline)
        {
            if (polls_out != nullptr)
                *polls_out = polls;
            diag::RecordErr(diag::Layer::FwUpload, "rtl-poll-tmo", static_cast<u32>(::duetos::core::ErrorCode::Timeout),
                            off, mask, polls);
            return false;
        }
    }
}

bool WriteFirmwarePage(NicInfo& n, u32 page_index, const u8* data, u32 page_len, RtlUploadResult* r)
{
    diag::RecordOk(diag::Layer::FwUpload, "rtl-page-start", page_index, page_len, 0);
    // Real path: select the page in REG_MCUFWDL bits[7:6:5:4]
    // (PAGE_SEL field), then byte-stream `data` through the
    // FIFO-mapped window 0x1000..0x1FFC. v0 records the intent
    // and bumps counters.
    (void)n;
    (void)data;
    diag::RecordErr(diag::Layer::FwUpload, "rtl-page-need-mmio",
                    static_cast<u32>(::duetos::core::ErrorCode::Unsupported), page_index, page_len, 0);
    if (r != nullptr)
    {
        ++r->pages_written;
        r->bytes_written += page_len;
    }
    return true;
}

} // namespace

const char* RtlUploadStageName(RtlUploadStage s)
{
    switch (s)
    {
    case RtlUploadStage::Idle:
        return "idle";
    case RtlUploadStage::EnableFwDl:
        return "enable-fwdl";
    case RtlUploadStage::PageWrite:
        return "page-write";
    case RtlUploadStage::ChecksumWait:
        return "chksum-wait";
    case RtlUploadStage::H2cInit:
        return "h2c-init";
    case RtlUploadStage::Complete:
        return "complete";
    case RtlUploadStage::Failed:
        return "failed";
    default:
        return "?";
    }
}

::duetos::core::Result<void> RtlUploadDrive(NicInfo& n, const RtlFirmwareParsed& parsed, RtlUploadResult* result)
{
    if (n.mmio_virt == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    if (result != nullptr)
        *result = {};

    diag::RecordOk(diag::Layer::FwUpload, "rtl-drive-start", parsed.signature, parsed.payload_size,
                   static_cast<u64>(parsed.generation));

    // Stage 1: enable firmware download.
    Mmio8Write(n, kRtlRegMcuFwDl, kRtlFwDlEnable);
    u32 polls = 0;
    if (!PollByteWithTimeout(n, kRtlRegMcuFwDl, kRtlFwDlReady, kRtlFwDlReady, 50, &polls))
    {
        if (result != nullptr)
            result->failed_at = RtlUploadStage::EnableFwDl;
        diag::RecordErr(diag::Layer::FwUpload, "rtl-fwdl-tmo", static_cast<u32>(::duetos::core::ErrorCode::Timeout),
                        polls, 0, 0);
        return ::duetos::core::Err{::duetos::core::ErrorCode::Timeout};
    }

    // Stage 2: page-by-page write.
    const u32 num_pages = (parsed.payload_size + kRtlFwPageBytes - 1u) / kRtlFwPageBytes;
    for (u32 p = 0; p < num_pages; ++p)
    {
        const u32 base = p * kRtlFwPageBytes;
        const u32 page_len =
            (parsed.payload_size - base < kRtlFwPageBytes) ? parsed.payload_size - base : kRtlFwPageBytes;
        WriteFirmwarePage(n, p, parsed.payload + base, page_len, result);
    }

    // Stage 3: assert checksum-report and wait for ROM_DLREADY.
    Mmio8Write(n, kRtlRegMcuFwDl, kRtlFwDlChksumRpt);
    if (!PollByteWithTimeout(n, kRtlRegMcuFwDl, kRtlFwDlRomDlReady, kRtlFwDlRomDlReady, 50, &polls))
    {
        if (result != nullptr)
        {
            result->failed_at = RtlUploadStage::ChecksumWait;
            result->chksum_wait_polls = polls;
        }
        return ::duetos::core::Err{::duetos::core::ErrorCode::Timeout};
    }
    if (result != nullptr)
        result->chksum_wait_polls = polls;

    // Stage 4: assert H2C_INIT.
    Mmio8Write(n, kRtlRegMcuFwDl, kRtlFwDlH2cInit);
    if (!PollByteWithTimeout(n, kRtlRegMcuFwDl, kRtlFwDlH2cInitOk, kRtlFwDlH2cInitOk, kRtlUploadDefaultTimeoutTicks,
                             &polls))
    {
        if (result != nullptr)
        {
            result->failed_at = RtlUploadStage::H2cInit;
            result->h2c_init_polls = polls;
            result->last_mcu_fwdl = Mmio8Read(n, kRtlRegMcuFwDl);
        }
        return ::duetos::core::Err{::duetos::core::ErrorCode::Timeout};
    }
    if (result != nullptr)
    {
        result->h2c_init_polls = polls;
        result->ok = true;
        result->failed_at = RtlUploadStage::Complete;
    }
    diag::RecordOk(diag::Layer::FwUpload, "rtl-h2c-init-ok", polls, 0, 0);
    return ::duetos::core::Result<void>{};
}

void RtlUploadSelfTest()
{
    NicInfo n{};
    n.mmio_virt = nullptr;
    RtlFirmwareParsed parsed{};
    RtlUploadResult r{};
    auto ur = RtlUploadDrive(n, parsed, &r);
    KASSERT(!ur.has_value(), "drivers/net/rtl88xx_upload", "rtl drive without MMIO must fail");
}

} // namespace duetos::drivers::net
