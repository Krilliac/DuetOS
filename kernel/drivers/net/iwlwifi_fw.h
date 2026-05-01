#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — Intel iwlwifi microcode (TLV) parser.
 *
 * The iwlwifi family ships its operational microcode as a TLV blob:
 * a 24-byte zero/magic prelude, a 64-byte human-readable name, a
 * version dword, a build dword, an 8-byte ignore field, then a
 * stream of `(u32 type, u32 length, u8 payload[length], pad)` TLV
 * records — each padded up to a 4-byte boundary — until end-of-blob.
 * The format is documented by Intel's firmware tree and mirrored by
 * Linux's `drivers/net/wireless/intel/iwlwifi/iwl-drv.c` and the
 * macOS port in OpenIntelWireless/itlwm.
 *
 * This parser is freestanding (no heap, no kernel-only deps beyond
 * `util/types.h`) and clean-room — only the Intel-defined header
 * layout + TLV identifiers are carried over from the public iwlwifi
 * firmware-format specification. It validates the magic + zero
 * preamble, walks the TLV stream, and populates an
 * `IwlFirmwareParsed` view that points back into the caller's blob
 * (no copying, no allocation).
 *
 * Scope (v0):
 *   - Validate header (zero / magic).
 *   - Walk every TLV record; bail on malformed length.
 *   - Categorize the section TLVs (INST / DATA / INIT / INIT_DATA /
 *     SEC_RT / SEC_INIT / SEC_WOWLAN) by storing pointer + size.
 *   - Capture FLAGS, NUM_OF_CPU, FW_VERSION dwords.
 *   - Count unknown TLVs in `unknown_records` so a caller can spot
 *     a wildly-out-of-band blob without losing the parse.
 *
 * Out of scope (deferred):
 *   - Section-header (`iwl_ucode_section`) parsing inside SEC_*
 *     payloads — only the outer TLV envelope is recorded for v0.
 *   - PNVM / IML / debug-region sections.
 *   - Signature verification.
 *
 * Threading: pure function. No global state. Safe from any context
 * where the caller already holds `req.data` valid for the duration.
 */

namespace duetos::drivers::net
{

inline constexpr u32 kIwlFwTlvMagic = 0x0A4C5749u; // "IWL\n" LE
// Header layout: 4 (zero) + 4 (magic) + 64 (name) + 4 (ver) + 4 (build)
// + 8 (ignore) = 88 bytes. The TLV stream begins immediately at +88.
inline constexpr u64 kIwlFwHeaderBytes = 4 + 4 + 64 + 4 + 4 + 8;
static_assert(kIwlFwHeaderBytes == 88, "iwl-fw header is 88 bytes");

inline constexpr u32 kIwlTlvHumanReadableLen = 64;

// Subset of the iwlwifi TLV identifier space we recognize. Values
// match Intel's `iwl_ucode_tlv_type` enum exactly (forever-stable
// ABI in the firmware blob format). Unknown types are still walked
// past — they bump `unknown_records` rather than fail the parse.
enum class IwlTlvType : u32
{
    Invalid = 0,
    Inst = 1,
    Data = 2,
    Init = 3,
    InitData = 4,
    Boot = 5,
    ProbeMaxLen = 6,
    Pan = 7,
    RuntEvtlogPtr = 8,
    RuntEvtlogSize = 9,
    RuntErrlogPtr = 10,
    InitEvtlogPtr = 11,
    InitEvtlogSize = 12,
    InitErrlogPtr = 13,
    EnhanceSensTbl = 14,
    PhyCalibrationSize = 15,
    WowlanInst = 16,
    WowlanData = 17,
    Flags = 18,
    SecRt = 19,
    SecInit = 20,
    SecWowlan = 21,
    DefCalib = 22,
    PhySku = 23,
    SecureSecRt = 24,
    SecureSecInit = 25,
    SecureSecWowlan = 26,
    NumOfCpu = 27,
    Cscheme = 28,
    ApiChangesSet = 29,
    EnabledCapabilities = 30,
    NScanChannels = 31,
    Paging = 32,
    SecRtUsniffer = 34,
    FwVersion = 36,
    FwDbgDest = 38,
    FwDbgConf = 39,
    FwDbgTrigger = 40,
    CmdVersions = 48,
    FwGscanCapa = 50,
    FwMemSeg = 51,
    Iml = 52,
    UmacDebugAddrs = 54,
    LmacDebugAddrs = 55,
    FwRecoveryInfo = 57,
    HwType = 58,
    FwFseqVersion = 60,
    PnvmVersion = 62,
    PnvmSku = 64,
    TypeBufferAllocation = 0x1000005u,
};

struct IwlFwSection
{
    // Pointer back into the firmware blob (not owned). Null if the
    // section was not present in the blob.
    const u8* data;
    u32 size;
};

struct IwlFirmwareParsed
{
    // True iff the magic / zero preamble validated and at least one
    // TLV record walked cleanly.
    bool valid;

    // Versioning. `human_readable` is the 64-byte ASCII name from
    // the header (NUL-terminated by the parser). `ver_packed` is
    // the 32-bit packed version dword. `build` is the build number
    // dword.
    char human_readable[kIwlTlvHumanReadableLen + 1];
    u32 ver_packed;
    u32 build;

    // Legacy fixed-section payloads. These map directly to TLV
    // records 1..4. Newer firmware may leave them empty and ship
    // SEC_RT-style sections instead — that's `sec_rt`.
    IwlFwSection inst;
    IwlFwSection data;
    IwlFwSection init;
    IwlFwSection init_data;

    // SEC_RT — runtime image. Modern firmware (8000+) stores
    // multiple SEC_RT records back-to-back; we record the first
    // one's payload pointer + size and the total `sec_rt_count`
    // so a future driver can re-walk for the rest.
    IwlFwSection sec_rt_first;
    u32 sec_rt_count;

    // Other recognised TLVs we record without semantic interpretation.
    u32 flags;      // IWL_UCODE_TLV_FLAGS payload (first dword).
    u32 num_of_cpu; // IWL_UCODE_TLV_NUM_OF_CPU payload.
    u32 fw_version; // IWL_UCODE_TLV_FW_VERSION first dword.
    u32 phy_sku;    // IWL_UCODE_TLV_PHY_SKU payload (first dword).
    u32 hw_type;    // IWL_UCODE_TLV_HW_TYPE payload (first dword).

    // Bookkeeping.
    u32 total_records;   // every TLV record we walked past
    u32 unknown_records; // records whose type we don't recognise
    u32 walked_bytes;    // header + every TLV consumed
    u32 invalid_records; // TLVs whose declared length overflowed the blob
};

/// Parse an iwlwifi firmware blob. The output `parsed` is populated
/// with views into `blob`, so `blob` MUST remain valid for the
/// lifetime of `parsed`.
///
/// Returns:
///   - `Ok` on a structurally valid blob (header preamble validated +
///     at least one TLV record walked).
///   - `Err{InvalidArgument}` for null/short input.
///   - `Err{Corrupt}` for bad magic / zero preamble.
///   - `Err{Corrupt}` if a TLV's declared length overflows the blob.
::duetos::core::Result<void> IwlFirmwareParse(const u8* blob, u32 blob_size, IwlFirmwareParsed* parsed);

/// Pretty-print a 1-line summary to the kernel serial log for use
/// during driver bring-up. Idempotent / no allocation.
void IwlFirmwareLog(const IwlFirmwareParsed& parsed);

/// Boot-time self-test. Constructs a synthetic TLV blob in a static
/// buffer and asserts the parser pulls the expected fields out.
/// Logs `[iwl-fw] selftest pass/fail` and panics on failure.
void IwlFirmwareSelfTest();

} // namespace duetos::drivers::net
