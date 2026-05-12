#pragma once

#include "drivers/net/mt76.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — MediaTek mt76 firmware header parser.
 *
 * Modern MediaTek Wi-Fi firmware (MT7921 / MT7922 / MT7925 / MT7915
 * generations) ships as a v3 container:
 *
 *   +0x00  char[12]  ident   "__MT76__"  / padding (varies)
 *   +0x0C  u32       fw_ver
 *   +0x10  u32       build_date
 *   +0x14  u32       n_region
 *   ...    region[n_region]  (per-region offset/size/load_addr)
 *
 * Earlier mt76 chips (MT7615/MT7663) use a simpler "FW_V3" header
 * with magic `__MT76__` or `MTK_FW_HDR` and a single-region body.
 * MT7921+ embeds patch firmware (`WIFI_RAM_CODE_*.bin`) plus ROM
 * patches (`WIFI_MT7961_patch_mcu_*.bin`).
 *
 * For v0 we only need to (a) refuse obviously-bad blobs by size and
 * (b) detect the v3 magic so a future upload state machine can pick
 * the right state-machine flavour without re-reading the file. The
 * actual region walk lands when the upload code does.
 *
 * Reference: Linux `drivers/net/wireless/mediatek/mt76/mt76_connac_mcu.h`
 * and `mt7921/init.c::mt7921_load_firmware`. Numeric magic + bytes
 * are hardware ABI; copying them is fine.
 *
 * Threading: pure function over caller-owned bytes. No global state.
 */

namespace duetos::drivers::net
{

inline constexpr u32 kMt76FwMinBytes = 8u * 1024;
inline constexpr u32 kMt76FwMaxBytes = 2u * 1024 * 1024;

enum class Mt76FwFlavour : u8
{
    Unknown = 0,
    HdrV3 = 1,    // v3 container — `__MT76__` magic
    RomPatch = 2, // ROM patch image — `MTK_PATCH` magic
    Raw = 3,      // no recognised magic; treat as raw payload
};

struct Mt76FirmwareParsed
{
    bool valid;
    Mt76FwFlavour flavour;
    u32 declared_size;
    u32 fw_version;   // populated for HdrV3
    u32 build_date;   // populated for HdrV3
    u32 region_count; // populated for HdrV3, 0 otherwise
    u32 fletcher32;   // payload fingerprint for the boot log
};

::duetos::core::Result<void> Mt76FirmwareParse(const u8* blob, u32 blob_size, Mt76FirmwareParsed* parsed);
void Mt76FirmwareLog(const Mt76FirmwareParsed& parsed);
void Mt76FirmwareSelfTest();
const char* Mt76FwFlavourName(Mt76FwFlavour f);

/// Canonical firmware basename for an mt76 family. Returns
/// nullptr for `Unknown`. Names follow the `linux-firmware`
/// distribution under `mediatek/`.
const char* Mt76FirmwareBasenameForFamily(Mt76Family family);

} // namespace duetos::drivers::net
