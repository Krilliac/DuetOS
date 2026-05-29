/*
 * DuetOS — AMD GFX9 CP microcode upload. See amd_cp_ucode.h.
 *
 * Halt-mask constants proven at COMPILE time. The upload sequence is
 * gated on a live AMD BAR5 and unverified on silicon (no AMD model in
 * QEMU) — needs a real Vega/Navi card with the gfx_*.bin firmware
 * present under the open-firmware path.
 */

#include "drivers/gpu/amd_cp_ucode.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "drivers/gpu/amd_gfx_fw.h"
#include "drivers/gpu/amd_gpu.h"
#include "loader/firmware_loader.h"
#include "log/klog.h"

namespace duetos::drivers::gpu::amd
{

static_assert(kAmdCeHalt == 0x01000000u, "CE_HALT");
static_assert(kAmdPfpHalt == 0x04000000u, "PFP_HALT");
static_assert(kAmdMeHalt == 0x10000000u, "ME_HALT");
static_assert(kAmdCpHaltAll == 0x15000000u, "CP halt-all (ME|PFP|CE)");

namespace
{

// Load one engine's microcode: FwLoad + AmdGfxFwParse, then stream the
// payload dwords into `data_reg` (the ADDR register auto-increments
// from 0), and write the trailing ucode version to `addr_reg`.
bool LoadEngine(void* bar5, const char* basename, u64 addr_reg, u64 data_reg)
{
    ::duetos::core::FwLoadRequest req{};
    req.vendor = "amd-gpu";
    req.basename = basename;
    req.min_bytes = kAmdCommonFwHeaderBytes;
    req.max_bytes = 0;
    auto fw = ::duetos::core::FwLoad(req);
    if (!fw.has_value())
        return false;

    AmdGfxFwParsed parsed{};
    auto pr = AmdGfxFwParse(fw.value().data, static_cast<u32>(fw.value().size), &parsed);
    if (!pr.has_value() || !parsed.valid || parsed.ucode == nullptr)
    {
        ::duetos::core::FwRelease(fw.value());
        return false;
    }

    AmdReg32Write(bar5, addr_reg, 0);
    for (u32 i = 0; i < parsed.ucode_dword_count; ++i)
        AmdReg32Write(bar5, data_reg, parsed.ucode[i]);
    AmdReg32Write(bar5, addr_reg, parsed.ucode_version); // documented trailing version write

    arch::SerialWrite("[gpu/amd/ucode] loaded ");
    arch::SerialWrite(basename);
    arch::SerialWrite(" dwords=");
    arch::SerialWriteHex(parsed.ucode_dword_count);
    arch::SerialWrite("\n");
    ::duetos::core::FwRelease(fw.value());
    return true;
}

} // namespace

::duetos::core::Result<void> AmdCpLoadMicrocode(void* bar5)
{
    if (bar5 == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::NotReady};

    // Halt PFP/CE/ME before touching ucode RAM.
    AmdReg32Write(bar5, kAmdRegCpMeCntl, kAmdCpHaltAll);

    const bool pfp = LoadEngine(bar5, "gfx_pfp.bin", kAmdRegCpPfpUcodeAddr, kAmdRegCpPfpUcodeData);
    const bool ce = LoadEngine(bar5, "gfx_ce.bin", kAmdRegCpCeUcodeAddr, kAmdRegCpCeUcodeData);
    const bool me = LoadEngine(bar5, "gfx_me.bin", kAmdRegCpMeRamWaddr, kAmdRegCpMeRamData);

    // RLC (optional for the CP-alive gate): disable F32, load, re-enable.
    // Power-gating left off for the minimal path.
    const u32 rlc_cntl = AmdReg32(bar5, kAmdRegRlcCntl);
    AmdReg32Write(bar5, kAmdRegRlcCntl, rlc_cntl & ~kAmdRlcEnableF32);
    if (LoadEngine(bar5, "gfx_rlc.bin", kAmdRegRlcGpmUcodeAddr, kAmdRegRlcGpmUcodeData))
        AmdReg32Write(bar5, kAmdRegRlcCntl, rlc_cntl | kAmdRlcEnableF32);

    // Un-halt so the CP starts fetching PM4 from the ring.
    AmdReg32Write(bar5, kAmdRegCpMeCntl, 0);

    if (pfp && ce && me)
    {
        arch::SerialWrite("[gpu/amd/ucode] CP microcode loaded (pfp+ce+me), CP un-halted\n");
        return {};
    }
    KLOG_WARN("drivers/gpu/amd", "CP microcode incomplete (missing gfx_pfp/ce/me.bin) — CP stays inert");
    return ::duetos::core::Err{::duetos::core::ErrorCode::NotFound};
}

void AmdCpUcodeSelfTest()
{
    if (kAmdCpHaltAll == 0x15000000u && kAmdCeHalt == 0x01000000u && kAmdPfpHalt == 0x04000000u &&
        kAmdMeHalt == 0x10000000u)
    {
        arch::SerialWrite("[gpu/amd/ucode] selftest PASS (CP halt-mask constants compile-verified)\n");
        return;
    }
    KBP_PROBE_V(::duetos::debug::ProbeId::kBootSelftestFail, 0x4155u /* 'AU' */);
    arch::SerialWrite("[gpu/amd/ucode] selftest FAIL (halt masks)\n");
}

} // namespace duetos::drivers::gpu::amd
