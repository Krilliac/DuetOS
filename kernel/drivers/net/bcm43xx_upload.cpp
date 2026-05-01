#include "drivers/net/bcm43xx_upload.h"

#include "core/panic.h"
#include "net/wireless/wifi_diag.h"
#include "time/tick.h"

namespace duetos::drivers::net
{

namespace
{

namespace diag = duetos::net::wireless::diag;

u32 Mmio32Read(const NicInfo& n, u32 off)
{
    if (n.mmio_virt == nullptr)
        return 0xFFFFFFFFu;
    const u32 v = *reinterpret_cast<volatile u32*>(static_cast<u8*>(n.mmio_virt) + off);
    diag::Record(diag::Layer::FwUpload, "bcm-r32", off, v, 0, 0, "bcm");
    return v;
}

void Mmio32Write(const NicInfo& n, u32 off, u32 v)
{
    if (n.mmio_virt == nullptr)
        return;
    *reinterpret_cast<volatile u32*>(static_cast<u8*>(n.mmio_virt) + off) = v;
    diag::Record(diag::Layer::FwUpload, "bcm-w32", off, v, 0, 0, "bcm");
}

bool PollMaskWithTimeout(NicInfo& n, u32 off, u32 mask, u32 expect, u32 timeout_ticks, u32* polls_out)
{
    const u64 deadline = duetos::time::TickCount() + timeout_ticks;
    u32 polls = 0;
    for (;;)
    {
        ++polls;
        const u32 v = Mmio32Read(n, off);
        if ((v & mask) == expect)
        {
            if (polls_out != nullptr)
                *polls_out = polls;
            diag::RecordOk(diag::Layer::FwUpload, "bcm-poll-hit", off, mask, polls);
            return true;
        }
        if (duetos::time::TickCount() >= deadline)
        {
            if (polls_out != nullptr)
                *polls_out = polls;
            diag::RecordErr(diag::Layer::FwUpload, "bcm-poll-tmo", static_cast<u32>(::duetos::core::ErrorCode::Timeout),
                            off, mask, polls);
            return false;
        }
    }
}

void UploadShmRecord(NicInfo& n, u32 base_off, const u8* data, u32 size, const char* tag)
{
    diag::RecordOk(diag::Layer::FwUpload, tag, base_off, size, 0);
    // Real implementation: for each 32-bit word, write
    // SHM_CONTROL = (base_off + word_index*4), then SHM_DATA = word.
    // v0 just records the intent + the would-be word count.
    const u32 words = size / 4u;
    for (u32 i = 0; i < words && i < 4; ++i)
    {
        // Record only the first 4 words to keep the diag ring
        // useful — full upload would be tens of thousands of
        // events.
        Mmio32Write(n, kBcmRegShmControl, base_off + i * 4u);
        const u32 word = (static_cast<u32>(data[i * 4]) << 0) | (static_cast<u32>(data[i * 4 + 1]) << 8) |
                         (static_cast<u32>(data[i * 4 + 2]) << 16) | (static_cast<u32>(data[i * 4 + 3]) << 24);
        Mmio32Write(n, kBcmRegShmData, word);
    }
    // After the 4-word teaser, log a single summary event covering
    // the rest. This mirrors the technique used by Linux's
    // mac80211 trace points: log first/last + count.
    if (words > 4)
        diag::RecordOk(diag::Layer::FwUpload, "bcm-shm-bulk", words - 4, base_off + 16, 0);
}

} // namespace

const char* BcmUploadStageName(BcmUploadStage s)
{
    switch (s)
    {
    case BcmUploadStage::Idle:
        return "idle";
    case BcmUploadStage::BringOutOfReset:
        return "out-of-reset";
    case BcmUploadStage::StopMac:
        return "stop-mac";
    case BcmUploadStage::UploadUcode:
        return "upload-ucode";
    case BcmUploadStage::UploadPcm:
        return "upload-pcm";
    case BcmUploadStage::UploadIv:
        return "upload-iv";
    case BcmUploadStage::StartUcode:
        return "start-ucode";
    case BcmUploadStage::Complete:
        return "complete";
    case BcmUploadStage::Failed:
        return "failed";
    default:
        return "?";
    }
}

::duetos::core::Result<void> BcmUploadDrive(NicInfo& n, const BcmFirmwareParsed& parsed, BcmUploadResult* result)
{
    if (n.mmio_virt == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    if (result != nullptr)
        *result = {};

    diag::RecordOk(diag::Layer::FwUpload, "bcm-drive-start", parsed.record_count, 0, 0);

    // Stage: stop the MAC.
    Mmio32Write(n, kBcmRegMacCtl, 0);
    u32 polls = 0;
    if (!PollMaskWithTimeout(n, kBcmRegMacCtl, kBcmMacCtlEnabled, 0, 50, &polls))
    {
        if (result != nullptr)
            result->failed_at = BcmUploadStage::StopMac;
        return ::duetos::core::Err{::duetos::core::ErrorCode::Timeout};
    }

    // Stage: upload sections via SHM.
    if (parsed.ucode != nullptr)
    {
        UploadShmRecord(n, kBcmShmUcode, parsed.ucode->payload, parsed.ucode->size, "bcm-shm-ucode");
        if (result != nullptr)
            result->ucode_words_written = parsed.ucode->size / 4u;
    }
    if (parsed.pcm != nullptr)
    {
        UploadShmRecord(n, kBcmShmPcm, parsed.pcm->payload, parsed.pcm->size, "bcm-shm-pcm");
        if (result != nullptr)
            result->pcm_words_written = parsed.pcm->size / 4u;
    }
    if (parsed.iv != nullptr)
    {
        UploadShmRecord(n, 0x8000, parsed.iv->payload, parsed.iv->size, "bcm-shm-iv");
        if (result != nullptr)
            result->iv_words_written = parsed.iv->size / 4u;
    }

    // Stage: start the ucode.
    Mmio32Write(n, kBcmRegMacCtl, kBcmMacCtlPsmRun | kBcmMacCtlEnabled);
    if (!PollMaskWithTimeout(n, kBcmRegIrqs, kBcmIrqUcodeStarted, kBcmIrqUcodeStarted, 200, &polls))
    {
        if (result != nullptr)
        {
            result->failed_at = BcmUploadStage::StartUcode;
            result->ucode_started_polls = polls;
            result->last_irqs = Mmio32Read(n, kBcmRegIrqs);
        }
        return ::duetos::core::Err{::duetos::core::ErrorCode::Timeout};
    }
    if (result != nullptr)
    {
        result->ucode_started_polls = polls;
        result->ok = true;
        result->failed_at = BcmUploadStage::Complete;
    }
    diag::RecordOk(diag::Layer::FwUpload, "bcm-ucode-running", polls, 0, 0);
    return ::duetos::core::Result<void>{};
}

void BcmUploadSelfTest()
{
    NicInfo n{};
    n.mmio_virt = nullptr;
    BcmFirmwareParsed parsed{};
    BcmUploadResult r{};
    auto ur = BcmUploadDrive(n, parsed, &r);
    KASSERT(!ur.has_value(), "drivers/net/bcm43xx_upload", "bcm drive without MMIO must fail");
}

} // namespace duetos::drivers::net
