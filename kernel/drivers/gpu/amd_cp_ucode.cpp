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

// Match a literal prefix without indexing beyond a short C string. The
// generation tags are supplied by the PCI classifier, but this helper keeps
// the public gate safe for malformed or synthetic callers too.
bool HasPrefix(const char* value, const char* prefix)
{
    if (value == nullptr || prefix == nullptr)
        return false;
    while (*prefix != '\0')
    {
        if (*value == '\0' || *value != *prefix)
            return false;
        ++value;
        ++prefix;
    }
    return true;
}

} // namespace

AmdCpFirmwarePath AmdCpFirmwarePathForFamily(const char* family)
{
    // The family tags are deliberately coarse strings from AmdGenTag:
    // gfx9-*, gfx10-* / gfx10.3-*, and gfx11-*. Keep this parser narrow
    // so a future GFX generation cannot silently enter an old upload path.
    if (HasPrefix(family, "gfx9") || HasPrefix(family, "gfx10"))
        return AmdCpFirmwarePath::kDirectHostUpload;
    if (HasPrefix(family, "gfx11"))
        return AmdCpFirmwarePath::kPspRequired;
    return AmdCpFirmwarePath::kUnsupported;
}

const char* AmdCpFirmwarePathName(AmdCpFirmwarePath path)
{
    switch (path)
    {
    case AmdCpFirmwarePath::kDirectHostUpload:
        return "direct-host-upload";
    case AmdCpFirmwarePath::kPspRequired:
        return "psp-required";
    case AmdCpFirmwarePath::kUnsupported:
    default:
        return "unsupported";
    }
}

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

    // RLC (optional for the CP-alive gate): disable F32, load, and only
    // re-enable it after all required CP images are present. This keeps
    // the whole path inert when a partial firmware set was supplied.
    const u32 rlc_cntl = AmdReg32(bar5, kAmdRegRlcCntl);
    AmdReg32Write(bar5, kAmdRegRlcCntl, rlc_cntl & ~kAmdRlcEnableF32);
    const bool rlc = LoadEngine(bar5, "gfx_rlc.bin", kAmdRegRlcGpmUcodeAddr, kAmdRegRlcGpmUcodeData);

    if (pfp && ce && me)
    {
        if (rlc)
            AmdReg32Write(bar5, kAmdRegRlcCntl, rlc_cntl | kAmdRlcEnableF32);
        // Un-halt only after every required CP image is resident so the
        // engine can never fetch a partially initialized instruction RAM.
        AmdReg32Write(bar5, kAmdRegCpMeCntl, 0);
        arch::SerialWrite("[gpu/amd/ucode] CP microcode loaded (pfp+ce+me), CP un-halted\n");
        return {};
    }
    KLOG_WARN("drivers/gpu/amd", "CP microcode incomplete (missing gfx_pfp/ce/me.bin) — CP stays inert");
    return ::duetos::core::Err{::duetos::core::ErrorCode::NotFound};
}

void AmdCpUcodeSelfTest()
{
    const bool halt_masks_ok = kAmdCpHaltAll == 0x15000000u && kAmdCeHalt == 0x01000000u &&
                               kAmdPfpHalt == 0x04000000u && kAmdMeHalt == 0x10000000u;
    const bool generation_gate_ok =
        AmdCpFirmwarePathForFamily("gfx9-raven") == AmdCpFirmwarePath::kDirectHostUpload &&
        AmdCpFirmwarePathForFamily("gfx10-navi1x") == AmdCpFirmwarePath::kDirectHostUpload &&
        AmdCpFirmwarePathForFamily("gfx10.3-navi2x") == AmdCpFirmwarePath::kDirectHostUpload &&
        AmdCpFirmwarePathForFamily("gfx11-navi3x") == AmdCpFirmwarePath::kPspRequired &&
        AmdCpFirmwarePathForFamily("amd-pre-gfx9-or-unknown") == AmdCpFirmwarePath::kUnsupported &&
        AmdCpFirmwarePathForFamily(nullptr) == AmdCpFirmwarePath::kUnsupported &&
        AmdCpFirmwarePathForFamily("") == AmdCpFirmwarePath::kUnsupported &&
        AmdCpFirmwarePathForFamily("g") == AmdCpFirmwarePath::kUnsupported &&
        AmdCpFirmwarePathForFamily("gf") == AmdCpFirmwarePath::kUnsupported &&
        AmdCpFirmwarePathForFamily("gfx") == AmdCpFirmwarePath::kUnsupported &&
        AmdCpFirmwarePathForFamily("gfx1") == AmdCpFirmwarePath::kUnsupported;

    if (halt_masks_ok && generation_gate_ok)
    {
        arch::SerialWrite("[gpu/amd/ucode] selftest PASS (CP halt masks + generation firmware gate)\n");
        return;
    }
    KBP_PROBE_V(::duetos::debug::ProbeId::kBootSelftestFail, 0x4155u /* 'AU' */);
    arch::SerialWrite("[gpu/amd/ucode] selftest FAIL (halt masks or generation firmware gate)\n");
}

} // namespace duetos::drivers::gpu::amd
