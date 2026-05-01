#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — Broadcom wireless firmware (b43 / brcm) header parser.
 *
 * The b43 format used by older Broadcom Wi-Fi silicon ships each
 * `.fw` file as one or more records, each prefixed by an 8-byte
 * BIG-ENDIAN header:
 *
 *   +0  u8   type      (FW_TYPE_UCODE=0x75 'u', FW_TYPE_PCM=0x70 'p',
 *                        FW_TYPE_IV=0x69 'i')
 *   +1  u8   version   (1 in OpenFW; vendor blobs use 0/1)
 *   +2  u16  reserved  (be16, ignored)
 *   +4  u32  size      (be32; payload byte count, not including the
 *                       8-byte header itself)
 *   +8  payload bytes
 *
 * For the legacy b43 driver, every official blob carries exactly
 * one record. The newer `brcmfmac` family uses a different format
 * (CLM blob + signed firmware header) — that one is out of scope
 * for v0; this parser walks the b43 wire format end-to-end and
 * the wireless-driver shell uses it as the v0 vehicle. Linux
 * references: drivers/net/wireless/broadcom/b43/main.c,
 * b43legacy/main.c. This is a clean-room implementation; only
 * the public byte-layout + record-type identifiers are carried over.
 *
 * Threading: pure function. No global state.
 */

namespace duetos::drivers::net
{

inline constexpr u32 kB43FwRecordHeaderBytes = 8;

inline constexpr u8 kB43FwTypeUcode = 0x75; // 'u'
inline constexpr u8 kB43FwTypePcm = 0x70;   // 'p'
inline constexpr u8 kB43FwTypeIv = 0x69;    // 'i'

inline constexpr u32 kBcmMaxRecords = 8;

struct BcmFwRecord
{
    u8 type; // see kB43FwType*; 0 if unused
    u8 version;
    u32 size;          // declared payload byte count
    const u8* payload; // pointer into the original blob
};

struct BcmFirmwareParsed
{
    bool valid;

    // Walked record table. v0 is bounded at `kBcmMaxRecords` to
    // avoid heap allocation; vendor blobs we've seen ship one
    // (legacy b43) or up to four (combined .fw) records.
    BcmFwRecord records[kBcmMaxRecords];
    u32 record_count;

    // Convenience: pointers to the first record of each type.
    // Null if that type wasn't present.
    const BcmFwRecord* ucode;
    const BcmFwRecord* pcm;
    const BcmFwRecord* iv;

    // Bookkeeping. `truncated` means the blob ended in the middle
    // of a record header / payload. A truncated blob still
    // returns Ok if at least one record parsed cleanly.
    bool truncated;
    u32 walked_bytes;

    // Number of records observed beyond `kBcmMaxRecords`. Treated
    // as informational — a future slice can either bump the cap
    // or accept the prefix.
    u32 dropped_records;
};

::duetos::core::Result<void> BcmFirmwareParse(const u8* blob, u32 blob_size, BcmFirmwareParsed* parsed);

void BcmFirmwareLog(const BcmFirmwareParsed& parsed);

void BcmFirmwareSelfTest();

const char* BcmFwTypeName(u8 type);

} // namespace duetos::drivers::net
