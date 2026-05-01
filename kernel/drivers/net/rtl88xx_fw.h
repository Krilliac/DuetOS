#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — Realtek wireless firmware (rtlwifi) header parser.
 *
 * The Realtek rtlwifi family ships its firmware as a fixed-header
 * blob followed by raw microcode. Two header generations exist:
 *
 *   v1 (rtl8192cu/rtl8723be/rtl8821ae/rtl8812ae): 32-byte header
 *       - 0x00  __le16 signature   (0x88C0/0x88E0/...)
 *       - 0x02  u8     category
 *       - 0x03  u8     function
 *       - 0x04  __le16 version
 *       - 0x06  u8     subversion
 *       - 0x07  u8     subsubversion
 *       - 0x08  u8[4]  date (mm dd hh mm)
 *       - 0x0C  __le16 ramcodesize
 *       - 0x0E  __le16 reserved
 *       - 0x10  __le32 svnindex
 *       - 0x14  __le32 reserved2
 *       - 0x18  __le32 reserved3
 *       - 0x1C  __le32 reserved4
 *       - 0x20  microcode payload begins
 *
 *   v2 (rtl8822be/rtl8852ae/rtw88/rtw89): 32-byte header with
 *       a different signature space; the parser exposes the same
 *       view, just flagged differently.
 *
 * Linux references: drivers/net/wireless/realtek/rtlwifi/rtl_phycfg.h,
 * drivers/net/wireless/realtek/rtw88/main.h, and
 * drivers/net/wireless/realtek/rtw89/fw.h. OpenWrt's rtl88xxxx ports
 * carry the same byte layout. This implementation is clean-room —
 * only the Realtek-defined byte layout + signature space are
 * carried over.
 *
 * Threading: pure function. No global state.
 */

namespace duetos::drivers::net
{

inline constexpr u32 kRtlFwHeaderBytes = 32;

// Known Realtek firmware signatures. The 16-bit signature lives at
// offset 0 of the header. Values are taken from rtlwifi's
// `RTL8192C_FW_SIGNATURE` / `RTL8723BE_FW_SIGNATURE` / etc. macros.
inline constexpr u16 kRtlSig8192c = 0x88C0;
inline constexpr u16 kRtlSig8192d = 0x92D0;
inline constexpr u16 kRtlSig8723b = 0x5300;
inline constexpr u16 kRtlSig8821 = 0x8821;
inline constexpr u16 kRtlSig8812 = 0x8812;
inline constexpr u16 kRtlSig8814 = 0x8814;
inline constexpr u16 kRtlSig8822b = 0x88B0;
inline constexpr u16 kRtlSig8852a = 0x8852;
inline constexpr u16 kRtlSig8723d = 0x53D0;

enum class RtlFwGeneration : u8
{
    Unknown = 0,
    Rtlwifi = 1, // rtl8192/8723/8821/8812/8814 family — fixed 32-byte header.
    Rtw88 = 2,   // rtl8822be/ce/8821cu — newer header format (rtw88 driver).
    Rtw89 = 3,   // rtl8852ae and later — Wi-Fi 6/6E (rtw89 driver).
};

struct RtlFirmwareParsed
{
    bool valid;
    RtlFwGeneration generation;

    u16 signature;
    u8 category;
    u8 function;
    u16 version;
    u8 subversion;
    u8 subsubversion;

    // 4-byte build date, raw bytes from the header (mm/dd/hh/mm).
    u8 date_month;
    u8 date_day;
    u8 date_hour;
    u8 date_minute;

    u16 ramcode_size; // declared payload size from the header.
    u32 svn_index;

    // View of the post-header microcode payload. Pointer back into
    // the original blob (not owned).
    const u8* payload;
    u32 payload_size;

    // Bookkeeping: did the declared `ramcode_size` agree with the
    // remaining-blob bytes? `size_mismatch` means the header
    // claimed N bytes but the blob had a different remainder.
    // The parser still returns Ok in that case — Realtek blobs
    // sometimes pad with zero bytes — but the flag lets a future
    // upload pass refuse.
    bool size_mismatch;
};

::duetos::core::Result<void> RtlFirmwareParse(const u8* blob, u32 blob_size, RtlFirmwareParsed* parsed);

void RtlFirmwareLog(const RtlFirmwareParsed& parsed);

void RtlFirmwareSelfTest();

const char* RtlFwGenerationName(RtlFwGeneration g);

} // namespace duetos::drivers::net
