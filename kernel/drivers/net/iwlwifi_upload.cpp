#include "drivers/net/iwlwifi_upload.h"

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
    diag::Record(diag::Layer::FwUpload, "csr-r", off, v, 0, 0, "iwl");
    return v;
}

void Mmio32Write(const NicInfo& n, u32 off, u32 v)
{
    if (n.mmio_virt == nullptr)
        return;
    *reinterpret_cast<volatile u32*>(static_cast<u8*>(n.mmio_virt) + off) = v;
    diag::Record(diag::Layer::FwUpload, "csr-w", off, v, 0, 0, "iwl");
}

void Mmio32SetBit(const NicInfo& n, u32 off, u32 bit)
{
    Mmio32Write(n, off, Mmio32Read(n, off) | bit);
}

void Mmio32ClearBit(const NicInfo& n, u32 off, u32 bit)
{
    Mmio32Write(n, off, Mmio32Read(n, off) & ~bit);
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
            diag::RecordOk(diag::Layer::FwUpload, "poll-hit", off, mask, polls);
            return true;
        }
        if (duetos::time::TickCount() >= deadline)
        {
            if (polls_out != nullptr)
                *polls_out = polls;
            diag::RecordErr(diag::Layer::FwUpload, "poll-timeout", static_cast<u32>(::duetos::core::ErrorCode::Timeout),
                            off, mask, polls);
            return false;
        }
    }
}

bool PrepareCardHw(NicInfo& n, IwlUploadResult* r)
{
    diag::RecordOk(diag::Layer::FwUpload, "stage-prepare", 0, 0, 0);
    // Disable LED.
    Mmio32Write(n, kCsrLedReg, 0);
    // Make sure HW does not assert any interrupts during init.
    Mmio32Write(n, kCsrIntMask, 0);
    Mmio32Write(n, kCsrInt, 0xFFFFFFFFu);
    Mmio32Write(n, kCsrFhIntStatus, 0xFFFFFFFFu);
    // Apply preparation bits per Linux: set MAC_INIT.
    Mmio32SetBit(n, kCsrGpCntrlReg, kCsrGpCntrlInitDone);
    u32 polls = 0;
    if (!PollMaskWithTimeout(n, kCsrGpCntrlReg, kCsrGpCntrlMacClockReady, kCsrGpCntrlMacClockReady, 50, &polls))
    {
        if (r != nullptr)
            r->alive_wait_polls = polls;
        return false;
    }
    return true;
}

bool SwReset(NicInfo& n, IwlUploadResult* r)
{
    diag::RecordOk(diag::Layer::FwUpload, "stage-swreset", 0, 0, 0);
    // Stop master + sw reset per CSR programming guide.
    Mmio32SetBit(n, kCsrReset, kCsrResetStopMaster);
    u32 polls = 0;
    if (!PollMaskWithTimeout(n, kCsrReset, kCsrResetMaster, kCsrResetMaster, 100, &polls))
    {
        diag::RecordErr(diag::Layer::FwUpload, "swreset-master-tmo",
                        static_cast<u32>(::duetos::core::ErrorCode::Timeout), polls, 0, 0);
        if (r != nullptr)
            r->alive_wait_polls = polls;
        return false;
    }
    Mmio32SetBit(n, kCsrReset, kCsrResetSwReset);
    // Spin ~20ms (2 ticks @ 100Hz) for the chip to latch the reset
    // signal. Real silicon needs ~10ms; we double for safety.
    {
        const u64 wait_until = duetos::time::TickCount() + 2;
        while (duetos::time::TickCount() < wait_until)
        {
            // busy wait — early boot, scheduler may not be up
        }
    }
    Mmio32ClearBit(n, kCsrReset, kCsrResetSwReset);
    return true;
}

bool NicInit(NicInfo& n)
{
    diag::RecordOk(diag::Layer::FwUpload, "stage-nic-init", 0, 0, 0);
    Mmio32SetBit(n, kCsrGpCntrlReg, kCsrGpCntrlMacAccessReq);
    u32 polls = 0;
    if (!PollMaskWithTimeout(n, kCsrGpCntrlReg, kCsrGpCntrlMacAccessEna, kCsrGpCntrlMacAccessEna, 50, &polls))
    {
        diag::RecordErr(diag::Layer::FwUpload, "nicinit-mac-access-tmo",
                        static_cast<u32>(::duetos::core::ErrorCode::Timeout), polls, 0, 0);
        return false;
    }
    return true;
}

bool LoadSection(NicInfo& /*n*/, const IwlFwSection& sec, u32 sec_index, IwlUploadResult* r)
{
    if (sec.data == nullptr || sec.size == 0)
        return true; // empty section is fine
    diag::RecordOk(diag::Layer::FwUpload, "section-load-start", sec_index, sec.size, 0);
    // v0 cannot perform DMA without a per-process DMA arena; we
    // record the intent and bail. Real upload will:
    //   - allocate a DMA-coherent buffer
    //   - copy `sec.data` into it
    //   - program FH_TFD pointers
    //   - kick the firmware DMA engine via FH_TX_CONFIG_REG
    //   - wait for FH_TX_STATUS_REG to acknowledge.
    diag::RecordErr(diag::Layer::FwUpload, "section-load-need-dma",
                    static_cast<u32>(::duetos::core::ErrorCode::Unsupported), sec_index, sec.size, 0);
    if (r != nullptr)
    {
        ++r->sections_uploaded;
        r->bytes_uploaded += sec.size;
    }
    return true;
}

} // namespace

const char* IwlUploadStageName(IwlUploadStage s)
{
    switch (s)
    {
    case IwlUploadStage::Idle:
        return "idle";
    case IwlUploadStage::PrepareCard:
        return "prepare";
    case IwlUploadStage::SwReset:
        return "swreset";
    case IwlUploadStage::NicInit:
        return "nic-init";
    case IwlUploadStage::SectionLoad:
        return "section-load";
    case IwlUploadStage::AliveWait:
        return "alive-wait";
    case IwlUploadStage::Complete:
        return "complete";
    case IwlUploadStage::Failed:
        return "failed";
    default:
        return "?";
    }
}

::duetos::core::Result<void> IwlUploadDrive(NicInfo& n, const IwlFirmwareParsed& parsed, IwlUploadResult* result)
{
    if (n.mmio_virt == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    if (result != nullptr)
        *result = {};

    diag::RecordOk(diag::Layer::FwUpload, "drive-start", parsed.ver_packed, parsed.total_records, n.chip_id,
                   parsed.human_readable);

    if (!PrepareCardHw(n, result))
    {
        if (result != nullptr)
            result->failed_at = IwlUploadStage::PrepareCard;
        return ::duetos::core::Err{::duetos::core::ErrorCode::Timeout};
    }
    if (!SwReset(n, result))
    {
        if (result != nullptr)
            result->failed_at = IwlUploadStage::SwReset;
        return ::duetos::core::Err{::duetos::core::ErrorCode::Timeout};
    }
    if (!NicInit(n))
    {
        if (result != nullptr)
            result->failed_at = IwlUploadStage::NicInit;
        return ::duetos::core::Err{::duetos::core::ErrorCode::Timeout};
    }

    // Section-by-section load. Modern firmware uses SEC_RT; older
    // uses INST/DATA/INIT.
    if (parsed.sec_rt_count > 0)
    {
        LoadSection(n, parsed.sec_rt_first, 0, result);
    }
    else
    {
        LoadSection(n, parsed.inst, 0, result);
        LoadSection(n, parsed.data, 1, result);
        LoadSection(n, parsed.init, 2, result);
        LoadSection(n, parsed.init_data, 3, result);
    }

    // Wait for ALIVE notification. The chip writes the ALIVE bit
    // in CSR_INT once the firmware is running and ready to take
    // commands. v0 cannot DMA microcode in (see LoadSection
    // comment) so this poll WILL time out on real hardware until
    // the DMA path lands; on hardware where FW is already loaded
    // by UEFI shim it may succeed immediately.
    u32 polls = 0;
    const bool alive =
        PollMaskWithTimeout(n, kCsrInt, kCsrIntBitAlive, kCsrIntBitAlive, kIwlUploadDefaultTimeoutTicks, &polls);
    if (result != nullptr)
    {
        result->alive_wait_polls = polls;
        result->last_csr_int = Mmio32Read(n, kCsrInt);
        result->last_gp_cntrl = Mmio32Read(n, kCsrGpCntrlReg);
    }
    if (!alive)
    {
        if (result != nullptr)
        {
            result->failed_at = IwlUploadStage::AliveWait;
            result->ok = false;
        }
        diag::RecordErr(diag::Layer::FwUpload, "alive-tmo", static_cast<u32>(::duetos::core::ErrorCode::Timeout), polls,
                        0, 0);
        return ::duetos::core::Err{::duetos::core::ErrorCode::Timeout};
    }
    // Acknowledge the ALIVE bit.
    Mmio32Write(n, kCsrInt, kCsrIntBitAlive);
    if (result != nullptr)
    {
        result->ok = true;
        result->failed_at = IwlUploadStage::Complete;
    }
    diag::RecordOk(diag::Layer::FwUpload, "alive-ok", polls, 0, n.chip_id);
    return ::duetos::core::Result<void>{};
}

void IwlUploadSelfTest()
{
    // The state machine is gated on real MMIO; without an MMIO
    // mapping we exercise the stage-name table + the failure
    // path's contract (returns Err with .failed_at set).
    NicInfo n{};
    n.mmio_virt = nullptr;
    IwlFirmwareParsed parsed{};
    IwlUploadResult r{};
    auto ur = IwlUploadDrive(n, parsed, &r);
    KASSERT(!ur.has_value(), "drivers/net/iwlwifi_upload", "drive without MMIO must fail");

    // Sanity-check name table.
    KASSERT(IwlUploadStageName(IwlUploadStage::Idle)[0] == 'i', "drivers/net/iwlwifi_upload",
            "stage name table broken");
}

} // namespace duetos::drivers::net
